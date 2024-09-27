import requests
import csv
import time

def NPM_crawler():
    github_link = 'https://github.com/nice-registry/all-the-package-names/blob/master/names.json'

def NVD_crawler():
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    API_KEY = ""
    start_index = 0
    all_vulnerabilities = []
    headers = {
        "apiKey": API_KEY
    }
    params = {
        'startIndex': start_index,
        'resultsPerPage': 2000
    }
    while True:
        response = requests.get(API_URL, headers=headers, params=params)
        print(response)
        if response.status_code == 200:
            data = response.json()
        if not data or 'vulnerabilities' not in data:
            break
        all_vulnerabilities.extend(data['vulnerabilities'])
        total_results = data['totalResults']
        current_results_count = len(all_vulnerabilities)
        if current_results_count >= total_results:
            break
        start_index += 2000
        time.sleep(1)
    return all_vulnerabilities

def githubAD_crawler():
    GITHUB_TOKEN = ""
    API_URL = "https://api.github.com/graphql"
    query_template = """
    {
    securityAdvisories(first: 100%s) {
        nodes {
            ghsaId
            publishedAt
            severity
            identifiers {
                type
                value
            }
            vulnerabilities(first: 5) {
                nodes {
                package {
                    name
                }
                vulnerableVersionRange
                firstPatchedVersion {
                    identifier
                }
            }
        }
        }
            pageInfo {
            hasNextPage
            endCursor
        }
    }
    }
    """
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    advisories = []
    has_next_page = True
    cursor = None
    while has_next_page:
        query = query_template % (cursor if cursor else "")
        response = requests.post(API_URL, json={'query': query}, headers=headers)
        if response.status_code == 200:
            data = response.json()
            advisories.extend(data['data']['securityAdvisories']['nodes'])
            page_info = data['data']['securityAdvisories']['pageInfo']
            has_next_page = page_info['hasNextPage']
            cursor = f', after: "{page_info['endCursor']}"'
        else:
            raise Exception(f"Query failed to run by returning code {response.status_code}. {response.text}")
    return advisories

def sourceclear_crawler(src_data_path):
    f = open(src_data_path, 'w')
    writer = csv.writer(f)
    src_url = "https://api.sourceclear.com/catalog/search?q=language%3Ajavascript%20type%3Avulnerability&page={}"
    for i in range(1, 10000):
        target_url = src_url.format(i)
        r = requests.get(target_url)
        if r.status_code == 503:
            break
        contents = r.json()["contents"]
        for cve in contents:
            if cve["model"]["cve"] == None:
                continue
            CVE_id = "CVE-" + cve["model"]["cve"]
            print(CVE_id)
            try:
                for component in cve["model"]["artifactComponents"]:
                    if component["componentCoordinateType"] != "NPM":
                        continue
                    component_id = component["componentName"]
                    for versionRange in component["versionRanges"]:
                        if versionRange["patch"] == "" or versionRange["patch"] == None:
                            continue
                        version_range = versionRange["versionRange"]
                        patch = versionRange["patch"]
                        writer.writerow([CVE_id, component_id, version_range, patch])
            except KeyError:
                continue
    f.close()
