import json
import subprocess
import os

def generate_sbom(package_path, output_file_name='sbom.json'):
    subprocess.run(f"npm sbom --sbom-format spdx > {output_file_name}", shell=True, cwd=package_path)

def load_sbom(package_path, file_name='sbom.json'):
    with open(os.path.join(package_path, file_name), 'r') as file:
        return json.load(file)

def extract_spdx_info(sbom_data):
    extracted_info = {
        'spdxVersion': sbom_data.get('spdxVersion'),
        'documentDescribes': sbom_data.get('documentDescribes', []),
        'packages': [
            {
                'name': pkg.get('name'),
                'SPDXID': pkg.get('SPDXID'),
                'versionInfo': pkg.get('versionInfo'),
                'licenseDeclared': pkg.get('licenseDeclared'),
                'checksums': pkg.get('checksums', [])
            } for pkg in sbom_data.get('packages', [])
        ],
        'relationships': [
            {
                'spdxElementId': rel.get('spdxElementId'),
                'relatedSpdxElement': rel.get('relatedSpdxElement'),
                'relationshipType': rel.get('relationshipType')
            } for rel in sbom_data.get('relationships', [])
        ]
    }
    return extracted_info


def main(package_path):
    generate_sbom(package_path)
    sbom_data = load_sbom(package_path)
    extracted_data = extract_spdx_info(sbom_data) 
    with open(os.path.join(package_path, 'extracted_data.json'), 'w') as file:
        json.dump(extracted_data, file, indent=2)

if __name__ == "__main__":
    package_path = './test-case/test1'
    main(package_path)