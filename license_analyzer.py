import json

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def get_dependency_relationship(sbom_data):
    dependency_relationships = []
    for relationship in sbom_data.get('relationships', []):
        relationship_type = relationship.get('relationshipType')
        if relationship_type == 'DEPENDENCY_OF':
            dependency_relationships.append(relationship)
    return dependency_relationships

def get_license_from_spdxid(id, sbom_data):
    for package in sbom_data.get('packages', []):
        if package.get('SPDXID') == id:
            return package.get('licenseDeclared')

def detect_conflict(dependency_license, dependent_license, conflict_dict):
    query = f"{dependent_license}---{dependency_license}"
    # print(query)
    if query in conflict_dict:
        return True
    return False

def load_conflict_res():
    merged_res = {}
    res_file_list = ['./res/C1.json', './res/C2.json', './res/C3.json']
    for res_file in res_file_list:
        merged_res.update(load_json(res_file))
    return merged_res

def main(sbom_path):
    sbom_data = load_json(sbom_path)
    conflict_dict = load_conflict_res()
    dependency_relationships = get_dependency_relationship(sbom_data)
    for dependency_relationship in dependency_relationships:
        dependency_id = dependency_relationship.get('spdxElementId')
        dependent_id = dependency_relationship.get('relatedSpdxElement')
        dependency_license = get_license_from_spdxid(dependency_id, sbom_data)
        dependent_license = get_license_from_spdxid(dependent_id, sbom_data)
        if detect_conflict(dependency_license, dependent_license, conflict_dict):
            print(f"Conflict detected between:\n dependency: {dependency_id}({dependency_license})\n dependent: {dependent_id}({dependent_license})")

if __name__ == '__main__':
    main('/data/sbom/test-case/test1/extracted_data.json')