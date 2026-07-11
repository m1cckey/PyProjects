import base64
import json



token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
def parser_JWT(token: str) -> dict:
    pars_l = []

    for encode_part in token.split('.')[:-1]:

        missing_padding = len(encode_part) % 4
        if missing_padding:
            encode_part += '=' * (4 - missing_padding)

        decoded_bytes = base64.urlsafe_b64decode(encode_part)
        decoded_text = decoded_bytes.decode('ascii')

        parsed_dict = json.loads(decoded_text)
        pars_l.append(parsed_dict)

    header = pars_l[0]
    payload = pars_l[1]
    signature = token.split('.')[2]
    padding = len(signature) % 4
    if padding:
        signature += '=' * (4 - padding)
    signature_bytes = base64.urlsafe_b64decode(signature)


    return header, payload, signature_bytes


def header_analys(header: dict) -> list:
    header_vuln_list = []
    for key, value in header.items():
        if key == 'alg' and value == 'none':
            header_vuln_list.append({'severity': 'Critical', 'description': 'unsigned token'})
        
