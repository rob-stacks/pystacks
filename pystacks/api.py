import urllib.request
import json


def simulate(
    block_id,
    auth_token,
    transactions,
    base_url="http://localhost:20443",
    endpoint="/v3/blocks/simulate/",
):
    url = base_url + endpoint + block_id
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
