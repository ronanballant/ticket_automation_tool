import requests
import json
import time

def scan_domain():
        analysis_url = "https://www.virustotal.com/api/v3/domains/torproject.org/analyse"

        headers = {
            "accept": "application/json",
            "x-apikey": "1f65e0a384968e78bc332777a6d3152428dca91099fc09617ccf31d117a0c3fd"
}

        response = requests.post(analysis_url, headers=headers)

        response_json = json.loads(response.text)
        response_data = response_json.get("data", None)

        if response.status_code == 200 and response_data:
            id = response_data.get("id", None)
            analyse_vt_rescan(id)
        else:
            id = None
            return
        
def analyse_vt_rescan(id):
    url = f"https://www.virustotal.com/api/v3/analyses/{id}"

    headers = {
        "accept": "application/json",
        "x-apikey": "1f65e0a384968e78bc332777a6d3152428dca91099fc09617ccf31d117a0c3fd"
    }

    attempt = 1
    scan_complete = False
    while scan_complete is False:
        response = requests.get(url, headers=headers)
        response_json = json.loads(response.text)
        response_data = response_json.get("data", None)
        status = response_json.get('data', {}).get('attributes', {}).get('status', "")
        
        if status == "completed":
            rescan = True
            scan_complete = True
            print("complete")
        else:
            attempt += 1
            print("retrying")
            
            if attempt == 13:
                scan_complete = True
                print("13 tries")
            else:
                time.sleep(5)      

    if response.status_code == 200 and response_data:
        id = response_data.get("id", None)
        analyse_vt_rescan(id)
    else:
        id = None
        return
    
scan_domain()