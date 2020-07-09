import requests
import json


"""read the configs from the file"""

config_file = open('./config.json').read()


"""load the json string as json object and extract the required configurations"""

config = json.loads(config_file)
aws_accounts = config['Accounts']
policy_criticality = config['PolicyCriticality']
environment_criticality = config['EnvironmentCriticality']

lacework_endpoint = "https://earnest.lacework.net/api/v1/"


def get_token():
    """request the temporary token to access the api"""

    lw_params = {"keyId": config['AccessKeyId'], "expiry_Time": 3600}
    lw_headers = {"X-LW-UAKS": config['SecretKey'], "Content-Type": "application/json"}

    response = requests.post(url=lacework_endpoint + "access/tokens", data=json.dumps(lw_params), headers=lw_headers)

    if response.status_code != 201:
        raise Exception("Unable to get token from lacework failing with error code %s Error Message: %s" % (
            response.status_code, response.text))

    bearer_token = json.loads(response.text)['data'][0]['token']
    return bearer_token


def get_info(aws_accountid, api_token):
    """request the endpoint to download the compliance report and parse the required fields"""

    lacework_report_url = lacework_endpoint + "external/compliance/aws/GetLatestComplianceReport" \
                                              "?AWS_ACCOUNT_ID=" + str(aws_accountid) + "&FILE_FORMAT=json"
    lacework_headers = {"Authorization": api_token}

    compliance_report = requests.get(url=lacework_report_url, headers=lacework_headers)

    if compliance_report.status_code != 201:
        raise Exception("Unable to download aws compliance report from Lacework. Error code %s Error Message %s" % (
            compliance_report.status_code, compliance_report.text))

    account_name = compliance_report.json()['data'][0]['accountAlias']
    report_time = compliance_report.json()['data'][0]['reportTime']

    risk_score = calculate_riskscore(compliance_report.json(), account_name)

    summary_json = compliance_report.json()['data'][0]['summary']

    output = json.dumps(
        {"Report_Time": report_time, "Report_Name": "CIS Benchmark and S3 Report", "Account_Name": account_name,
         "Account_Number": aws_accountid,
         "Resources_Accessed": summary_json[0]['ASSESSED_RESOURCE_COUNT'],
         "Resources_Violated": summary_json[0]['VIOLATED_RESOURCE_COUNT'],
         "Critical_Policy_violated": summary_json[0]
         ['NUM_SEVERITY_1_NON_COMPLIANCE'],
         "High_Policy_Violated": summary_json[0]['NUM_SEVERITY_2_NON_COMPLIANCE'],
         "Medium_Policy_Violated": summary_json[0]['NUM_SEVERITY_3_NON_COMPLIANCE'],
         "Low_Policy_Violated": summary_json[0]
         ['NUM_SEVERITY_4_NON_COMPLIANCE'], "Info_Policy_Violated": summary_json[0]
        ['NUM_SEVERITY_5_NON_COMPLIANCE'], "Compliant_Policy": summary_json[0]['NUM_COMPLIANT'],
         "Non_compliant_Policy": summary_json[0]['NUM_NOT_COMPLIANT'],
         "Total_Recommended_Policy": summary_json[0]['NUM_RECOMMENDATIONS'], "Risk_Score": risk_score})
    print(output)


def calculate_riskscore(lacework_response, account_name):
    """extract the severity of all the policies and convert it into a list
    Custom severity is list of corrosponding criticality score per severity defined in config file"""

    Severity = extract_values(lacework_response, 'SEVERITY')
    Custom_Severity = [get_severity_score(severity) for severity in Severity]

    assessed_resources = extract_values(lacework_response, 'ASSESSED_RESOURCE_COUNT')
    affected_resources = extract_values_array_count(lacework_response, 'VIOLATIONS')

    """Score per policy is calculated by  (affected resource/assessed resource) * Custom Severity"""
    score = sum(compute(a, b, c) for a, b, c in zip(affected_resources, assessed_resources, Custom_Severity))

    """max score is Total possible risk score of all policy accessed (compliant+non compliant) * 1 (where 1 is max 
    possible score per policy) """

    max_score = lacework_response['data'][0]['summary'][0]['NUM_COMPLIANT'] + \
                lacework_response['data'][0]['summary'][0]['NUM_NOT_COMPLIANT']
    # print(score, max_score)

    normalized_score = round((score / max_score) * 10 * environment_criticality[account_name], 2)
    # print(normalized_score)

    return normalized_score


def compute(num1, num2, num3):
    return (num1 / num2) * num3 if num1 and num2 and num3 else 0


def extract_values(json_obj, key):
    """Pull all values of specified key from nested JSON."""
    arr = []

    def extract(json_obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(json_obj, list):
            for item in json_obj:
                extract(item, arr, key)
        return arr

    results = extract(json_obj, arr, key)
    return results


def extract_values_array_count(json_obj, key):
    """Pull count of all violations for policies from nested JSON."""
    arr = []

    def extract(json_obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                if k == key:
                    if v is not None:
                        arr.append(len(v))
                    else:
                        arr.append(0)
                else:
                    extract(v, arr, key)
        elif isinstance(json_obj, list):
            for item in json_obj:
                extract(item, arr, key)
        return arr

    results = extract(json_obj, arr, key)
    return results


def get_severity_score(severity):
    if severity == 1:
        return policy_criticality['Critical']
    elif severity == 2:
        return policy_criticality['High']
    elif severity == 3:
        return policy_criticality['Medium']
    elif severity == 4:
        return policy_criticality['Low']
    elif severity == 5:
        return policy_criticality['Info']
    else:
        return None


def main():

    """loop over all aws accounts in config file to compute riskscores"""

    bearer_token = get_token()
    for i in range(0, len(aws_accounts)):
        aws_accountid = (aws_accounts[i]['accountNumber'])
        get_info(aws_accountid, bearer_token)


if __name__ == "__main__":
    main()
