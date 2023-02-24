import csv
import requests

# Define the base URL for the Google Safe Browsing API
safe_browsing_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY_HERE'

# Define the list of threat types to check for
threat_types = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION']

# Define the path to the CSV file
csv_path = 'URLlistnodup.csv'

# Define the path to the output CSV file
output_csv_path = 'URLlist.csv'

# Open the CSV file and read its contents into a list
with open(csv_path, 'r') as csv_file:
    csv_reader = csv.reader(csv_file)
    urls = [row[0] for row in csv_reader]

# Loop through each URL in the list and check if it's on the Google Safe Browsing list of known unsafe or suspicious URLs
results = []
for url in urls:
    print(f'Checking {url}...')
    params = {
        'threatInfo': {
            'threatTypes': threat_types,
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    response = requests.post(safe_browsing_url, json=params)
    if response.ok:
        data = response.json()
        if data.get('matches'):
            result = {'url': url, 'status': 'malicious or suspicious'}
            results.append(result)
            print(f'{url} is a known malicious or suspicious URL')
        else:
            result = {'url': url, 'status': 'safe'}
            results.append(result)
            print(f'{url} is a safe URL')
    else:
        result = {'url': url, 'status': f'potentially harmful with status code {response.status_code}'}
        results.append(result)
        print(f'{url} is a potentially harmful URL with status code {response.status_code}')

# Write the results to a CSV file
with open(output_csv_path, 'w', newline='') as output_csv_file:
    fieldnames = ['url', 'status']
    csv_writer = csv.DictWriter(output_csv_file, fieldnames=fieldnames)
    csv_writer.writeheader()
