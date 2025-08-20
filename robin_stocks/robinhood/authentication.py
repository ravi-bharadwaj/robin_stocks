"""Contains all functions for the purpose of logging in and out to Robinhood."""

import getpass
import os
import pickle
import random
import time
from robin_stocks.robinhood.helper import *
from robin_stocks.robinhood.urls import *


def generate_device_token():
    """This function will generate a token used when loggin on.

    :returns: A string representing the token.

    """
    rands = []
    for i in range(0, 16):
        r = random.random()
        rand = 4294967296.0 * r
        rands.append((int(rand) >> ((3 & i) << 3)) & 255)

    hexa = []
    for i in range(0, 256):
        hexa.append(str(hex(i + 256)).lstrip("0x").rstrip("L")[1:])

    id = ""
    for i in range(0, 16):
        id += hexa[rands[i]]

        if (i == 3) or (i == 5) or (i == 7) or (i == 9):
            id += "-"

    return id


def respond_to_challenge(challenge_id, sms_code):
    """This function will post to the challenge url.

    :param challenge_id: The challenge id.
    :type challenge_id: str
    :param sms_code: The sms code.
    :type sms_code: str
    :returns:  The response from requests.

    """
    url = challenge_url(challenge_id)
    payload = {"response": sms_code}
    return request_post(url, payload)


def login(
    username=None,
    password=None,
    store_session=True,
    pickle_path="",
    pickle_name="",
    code_file_path="",
    login_started_file_path="",
):
    """This function will effectively log the user into robinhood by getting an
    authentication token and saving it to the session header. By default, it
    will store the authentication token in a pickle file and load that value
    on subsequent logins.

    :param username: The username for your robinhood account, usually your email.
        Not required if credentials are already cached and valid.
    :type username: Optional[str]
    :param password: The password for your robinhood account. Not required if
        credentials are already cached and valid.
    :type password: Optional[str]
    :param scope: Specifies the scope of the authentication.
    :type scope: Optional[str]
    :param store_session: Specifies whether to save the log in authorization
        for future log ins.
    :type store_session: Optional[boolean]
    :param pickle_path: Allows users to specify the path of the pickle file.
        Accepts both relative and absolute paths.
    :param pickle_name: Allows users to name Pickle token file in order to switch
        between different accounts without having to re-login every time.
    :returns:  A dictionary with log in information. The 'access_token' keyword contains the access token, and the 'detail' keyword \
    contains information on whether the access token was generated or loaded from pickle file.

    """
    home_dir = os.path.expanduser("~")
    data_dir = os.path.join(home_dir, ".tokens")
    if pickle_path:
        if not os.path.isabs(pickle_path):
            # normalize relative paths
            pickle_path = os.path.normpath(os.path.join(os.getcwd(), pickle_path))
        data_dir = pickle_path
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    creds_file = "robinhood" + pickle_name.replace("@", "").replace(".", "") + ".pickle"
    pickle_path = os.path.join(data_dir, creds_file)
    # If authentication has been stored in pickle file then load it. Stops login server from being pinged so much.
    if os.path.isfile(pickle_path):
        # If store_session has been set to false then delete the pickle file, otherwise try to load it.
        # Loading pickle file will fail if the acess_token has expired.
        if store_session:
            try:
                with open(pickle_path, "rb") as f:
                    pickle_data = pickle.load(f)
                    access_token = pickle_data["access_token"]
                    token_type = pickle_data["token_type"]
                    refresh_token = pickle_data["refresh_token"]
                    set_login_state(True)
                    update_session("Authorization", "{0} {1}".format(token_type, access_token))
                    # Try to load account profile to check that authorization token is still valid.
                    res = request_get(
                        positions_url(), "pagination", {"nonzero": "true"}, jsonify_data=False
                    )
                    # Raises exception is response code is not 200.
                    res.raise_for_status()
                    return {
                        "access_token": access_token,
                        "token_type": token_type,
                        "expires_in": 689285,
                        "scope": "internal",
                        "detail": "logged in using authentication in {0}".format(creds_file),
                        "backup_code": None,
                        "refresh_token": refresh_token,
                    }
            except:
                os.remove(pickle_path)
                print(
                    "ERROR: There was an issue loading pickle file. Authentication may be expired - logging in normally.",
                    file=get_output(),
                )
                set_login_state(False)
                update_session("Authorization", None)
        else:
            os.remove(pickle_path)
    if not login_started_file_path or login_started_file_path == "":
        raise Exception("Login started file path not passed")
    if os.path.isfile(login_started_file_path):
        raise Exception("Login already in process")

    with open(file=login_started_file_path, mode="w") as f:
        f.write("login started")

    device_token = generate_device_token()
    request_id = generate_device_token()
    url = login_url()
    payload = {
        "client_id": "c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS",
        "create_read_only_secondary_token": True,
        "device_token": device_token,
        "expires_in": 689285,
        "grant_type": "password",
        "password": password,
        "request_id": request_id,
        "scope": "internal",
        "token_request_path": "/login",
        "username": username,
    }
    data = request_post(url, payload, ignore_403_status=True)
    # Handle case where mfa or challenge is required.
    if data:
        if "verification_workflow" in data:
            workflow_id = data["verification_workflow"]["id"]
            # _validate_sherrif_id(device_token=device_token, workflow_id=workflow_id, mfa_code=mfa_code)
            if _do_sheriff_validations(
                device_token=device_token,
                workflow_id=workflow_id,
                code_file_path=code_file_path,
            ):
                data = request_post(url, payload)
            else:
                raise Exception(  # pylint: disable=broad-exception-raised
                    "Unable to get verification_workflow"
                )
        # Update Session data with authorization or raise exception with the information present in data.
        if "access_token" in data:
            token = "{0} {1}".format(data["token_type"], data["access_token"])
            update_session("Authorization", token)
            set_login_state(True)
            data["detail"] = "logged in with brand new authentication code."
            if store_session:
                with open(pickle_path, "wb") as f:
                    pickle.dump(
                        {
                            "token_type": data["token_type"],
                            "access_token": data["access_token"],
                            "refresh_token": data["refresh_token"],
                            "device_token": payload["device_token"],
                        },
                        f,
                    )
                    if os.path.exists(login_started_file_path):
                        os.remove(login_started_file_path)
                    return True

        else:
            if "detail" in data:
                raise Exception(data["detail"])  # pylint: disable=broad-exception-raised
            raise Exception(  # pylint: disable=broad-exception-raised
                f"Received an error response {data}"
            )
    else:
        raise Exception(  # pylint: disable=broad-exception-raised
            "Error: unable to get token request submitted"
        )
    return data


def _do_sheriff_validations(device_token: str, workflow_id: str, code_file_path: str) -> bool:
    url = "https://api.robinhood.com/pathfinder/user_machine/"
    payload = {"device_id": device_token, "flow": "suv", "input": {"workflow_id": workflow_id}}
    data = request_post(url=url, payload=payload, json=True)
    if data and "id" in data:
        url = user_view_url(data["id"])
        user_view_response = request_get(url=url)
        if _process_user_view_response(
            user_view_response=user_view_response, code_file_path=code_file_path
        ):
            user_view_payload = {"sequence": 0, "user_input": {"status": "continue"}}
            approval_response = request_post(url=url, payload=user_view_payload, json=True)
            if "type_context" in approval_response:
                if (
                    "result" in approval_response["type_context"]
                    and approval_response["type_context"]["result"] == "workflow_status_approved"
                ):
                    return True
                raise Exception(  # pylint: disable=broad-exception-raised
                    f"result not in inquiries_response.type_context {approval_response['type_context']}"
                )
            raise Exception(  # pylint: disable=broad-exception-raised
                f"type_context not in inauiries response {approval_response}"
            )
    raise Exception(  # pylint: disable=broad-exception-raised
        f"invalid user_machine_response {data}"
    )


def _process_user_view_response(user_view_response, code_file_path) -> bool:
    if (
        user_view_response
        and "context" in user_view_response
        and "sheriff_challenge" in user_view_response["context"]
    ):
        challenge_type = user_view_response["context"]["sheriff_challenge"]["type"]
        if challenge_type == "prompt":
            return _validate_via_prompt(
                challenge_id=user_view_response["context"]["sheriff_challenge"]["id"],
            )
        elif challenge_type == "sms":
            return _validate_via_sms(
                challenge_id=user_view_response["context"]["sheriff_challenge"]["id"],
                code_file_path=code_file_path,
            )
        else:
            raise Exception(  # pylint: disable=broad-exception-raised
                f"Unsupported challenge type {challenge_type}"
            )
    raise Exception(  # pylint: disable=broad-exception-raised
        f"invalid response {user_view_response}"
    )


def _validate_via_prompt(challenge_id: str) -> bool:
    start_time = time.time()
    url = prompt_status_url(challenge_id)
    while time.time() - start_time < 120:
        res = request_get(url)
        if res and "challenge_status" in res:
            if res["challenge_status"] == "issued":
                time.sleep(10)
                continue
            if res["challenge_status"] == "validated":
                return True
    raise Exception("didn't approve in time, retry")  # pylint: disable=broad-exception-raised


def _validate_via_sms(challenge_id: str, code_file_path: str) -> bool:
    def _get_sms_code(code_file_path):
        start_time = time.time()
        if os.path.exists(code_file_path):
            os.remove(code_file_path)
        while time.time() - start_time < 120:
            if os.path.exists(code_file_path):
                time.sleep(2)
                with open(file=code_file_path, mode="r", encoding="utf-8") as mfa_file:
                    sms_code = mfa_file.read()
                    if not sms_code:
                        raise Exception(  # pylint: disable=broad-exception-raised
                            "sms code file is empty"
                        )
                    return sms_code
            time.sleep(2)
        raise Exception(  # pylint: disable=broad-exception-raised
            "didn't get sms code in time, retry"
        )

    url = challenge_url(challenge_id=challenge_id)
    request_post(url=url)
    challenge_payload = {"response": _get_sms_code(code_file_path=code_file_path)}
    challenge_response = request_post(url=url, payload=challenge_payload, json=True)
    if (
        challenge_response
        and "status" in challenge_response
        and challenge_response["status"] == "validated"
    ):
        return True
    raise Exception(  # pylint: disable=broad-exception-raised
        f"Challenge not validated {challenge_response}"
    )


@login_required
def logout():
    """Removes authorization from the session header.

    :returns: None

    """
    set_login_state(False)
    update_session("Authorization", None)
