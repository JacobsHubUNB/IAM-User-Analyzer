import boto3
import json
import networkx as nx
from urllib.parse import unquote 

#Script accessing AWS account
iam = boto3.client('iam') 

graph = nx.DiGraph()

#list containing the security threats of every policy of each role

Role_Security_Threats = {}

#=====================================================================
# DATA EXTRACTION AND PROCESSING
#=====================================================================

def analyze(statement, policyNode):
    rslt = {'Effect': '', 'Action': '', 'Resource': '', 'Risk': '', 'Description': ''}

    rslt['Effect'] = statement.get('Effect', 'Allow')
    rslt['Action'] = statement.get('Action', [])

    if isinstance(rslt['Action'], str):   # if it's just one string
        actions = [action]

    rslt['Resource'] = statement.get('Resource', [])

    if isinstance(rslt['Resource'], str):   # if it's just one string
        resources = [resource]

    for act in rslt['Actions']:
        if '*' in act:
            rslt['Risk'] = "MEDIUM"
        else:
            rslt['Risk'] = 'LOW'

    for resource in rslt['Resource']:
        if '*' in resource and 'MEDIUM' in rslt['Risk']:
            rslt['Risk'] = "HIGH"
            rslt['Description'] = 'Wildcard Action And Wildcard Resorces Detected!'
        elif '*' in resource or 'MEDIUM' in rslt['Risk'] :
             rslt['Risk'] = "MEDIUM"
             rslt['Description'] = "Warning Role Contains Wildcard Resource or Action"
        else:
            rslt['Risk'] = "LOW"
            rslt['Description'] = "Role Obeys Law of Least Privillage"
        graph.add_edge(policyNode, resource, Effect = rslt['Effect'], Action = rslt['Action'])
    
    return rslt

roles = iam.list_roles()['Roles']

#analyze every policy for every role

for role in roles:

    policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
    graph.add_node( role['RoleName'])
    Role_Security_Threats['Role_Analysis'] = {'RoleName': role['RoleName'], 'Policies': [] }

    for policy in policies:
        policy_name = policy['PolicyName']
        policyReport = {'Policy_Name': policy_name, 'Statement_Report': []} #Each Policy Statement Report
       
        graph.add_node(policy_name)
        graph.add_edge(role['RoleName'], policy_name)
        policy_statement = policy['PolicyDocument']['Statement']

        #Append Analysis of Each Statement to Statement Report List
        policyReport['Statement_Report'].append( analyze(policy_statement, policy_name))
        
    Role_Security_Threats['Role_Analysis']['Policies'].append(policyReport) #Append Policy Report of Every Role
    


#=====================================================================
# FINDINGS PRINITOUT AND JSON EXPORT
#=====================================================================

print("=" * 60)
print("         IAM SECURITY FINDINGS REPORT")
print("=" * 60)
print("\n")
for role in Role_Security_Threats:
    print(f"Role Name: {role['RoleName']}\n")
    for policy in role['Policies']:
        print(f'Policy: {policy['Policy_Name']}\n')
        print(json.dumps(policy['Statement_Report'], indent=4))



print(f"\n{'=' * 60}")
print(f"\n📊 Identity Graph Summary:")
print(f"   Nodes (roles, policies, resources): {graph.number_of_nodes()}")
print(f"   Edges (permission relationships):   {graph.number_of_edges()}")

graph_json = nx.node_link_data(graph)

with open("graph_export.json", "w") as f:
    json.dump(graph_json, f, indent=2)

print("\n💾 Graph exported to graph_export.json")