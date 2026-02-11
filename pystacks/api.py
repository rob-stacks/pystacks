import urllib.request
import json
from .block import NakamotoBlock
from io import BytesIO


def block_simulate(
    block_id,
    auth_token,
    transactions,
    profiler=False,
    use_cache=False,
    base_url="http://localhost:20443",
    endpoint="/v3/blocks/simulate/",
):
    url = base_url + endpoint + block_id

    query_string = ""

    if profiler:
        query_string += "profiler=1"

    if use_cache:
        query_string += "use_cache=1"

    if query_string:
        query_string = "?" + query_string

    json_blob = json.dumps(transactions)

    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
    }

    req = urllib.request.Request(
        url, data=json_blob.encode("utf-8"), headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        raise Exception("HTTP {}: {}".format(e.code, e.read().decode("utf8"))) from None


def block_replay(
    block_id,
    auth_token,
    profiler=False,
    use_cache=False,
    base_url="http://localhost:20443",
    endpoint="/v3/blocks/replay/",
):
    if isinstance(block_id, bytes):
        block_id = block_id.hex()

    if profiler:
        query_string += "profiler=1"

    if use_cache:
        query_string += "use_cache=1"

    if query_string:
        query_string = "?" + query_string

    url = "{}{}{}{}".format(base_url, endpoint, block_id)

    if profiler:
        url += "?profiler=1"

    headers = {
        "Authorization": auth_token,
    }

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        raise Exception("HTTP {}: {}".format(e.code, e.read().decode("utf8"))) from None


def block_v3(
    block_id,
    base_url="http://localhost:20443",
    endpoint="/v3/blocks/",
):
    url = base_url + endpoint + block_id

    req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = response.read()
            return NakamotoBlock.from_stream(BytesIO(data))
    except urllib.error.HTTPError as e:
        raise Exception("HTTP {}: {}".format(e.code, e.read().decode("utf8"))) from None


def block_by_height(
    block_height,
    base_url="http://localhost:20443",
    endpoint="/v3/blocks/height/",
):
    url = "{}{}{}".format(base_url, endpoint, block_height)

    req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = response.read()
            return NakamotoBlock.from_stream(BytesIO(data))
    except urllib.error.HTTPError as e:
        raise Exception("HTTP {}: {}".format(e.code, e.read().decode("utf8"))) from None


def call_read_only(
    sender,
    contract_address,
    contract_name,
    function_name,
    function_args=None,
    base_url="http://localhost:20443",
    endpoint="/v2/contracts/call-read/",
):
    url = (
        base_url
        + endpoint
        + contract_address
        + "/"
        + contract_name
        + "/"
        + function_name
    )

    serialized_args = []
    if function_args:
        for function_arg in function_args:
            stream = BytesIO()
            function_arg.to_stream(stream)
            stream.seek(0)
            serialized_args.append(stream.read().hex())

    json_blob = json.dumps({"sender": sender, "arguments": serialized_args})

    headers = {
        "Content-Type": "application/json",
    }

    req = urllib.request.Request(
        url, data=json_blob.encode("utf-8"), headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        raise Exception("HTTP {}: {}".format(e.code, e.read().decode("utf8"))) from None


def get_account(
    stx_address,
    base_url="http://localhost:20443",
    endpoint="/v2/accounts/",
):
    url = base_url + endpoint + stx_address

    req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req) as response:
            data = response.read()
            return json.loads(data)
    except urllib.error.HTTPError as e:
        raise Exception("HTTP {}: {}".format(e.code, e.read().decode("utf8"))) from None


def get_balance(
    stx_address,
    base_url="http://localhost:20443",
    endpoint="/v2/accounts/",
):
    account_data = get_account(stx_address, base_url, endpoint)
    return int(account_data["balance"], 16)
