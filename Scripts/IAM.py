import boto3
import json
import networkx as nx
from urllib.parse import unquote 

#Script accessing AWS account
iam = boto3.client('iam') 

graph = nx.DiGraph()

#list containing the security threats of every policy of each role

Role_Security_Threats = []

#=====================================================================
# DATA EXTRACTION AND PROCESSING
#=====================================================================

def analyze(statement, policyNode):
    rslt = {'Effect': '', 'Action': '', 'Resource': '', 'Risk': '', 'Description': ''}
    if isinstance(statement, dict):
        statement = [statement]
    counter = 1
    rslt['Effect'] = {}
    rslt['Action'] = {}
    rslt['Resource'] = {}
    rslt['Risk'] = {}
    rslt['Description'] = {}
    for stmt in statement:
        rslt['Effect'][counter] = stmt.get('Effect', 'Allow')
        rslt['Action'][counter] = stmt.get('Action', [])
        rslt['Resource'][counter] = stmt.get('Resource', [])
        counter+1

    for act in rslt['Action']:
        if '*' in rslt['Action'][act]:
            rslt['Risk'][act] = "MEDIUM"
        else:
            rslt['Risk'][act] = 'LOW'

    for resource in rslt['Resource']:
        if '*' in rslt['Resource'][resource] and 'MEDIUM' in rslt['Risk'][resource]:
            rslt['Risk'] = "HIGH"
            rslt['Description'] = 'Wildcard Action And Wildcard Resorces Detected!'
        elif '*' in rslt['Resource'][resource] or 'MEDIUM' in  rslt['Risk'][resource] :
             rslt['Risk'] = "MEDIUM"
             rslt['Description'] = "Warning Role Contains Wildcard Resource or Action"
        else:
            rslt['Risk'] = "LOW"
            rslt['Description'] = "Role Obeys Law of Least Privillage"
        graph.add_edge(policyNode,  rslt['Risk'][resource], Effect = rslt['Effect'][resource], Action = rslt['Action'][resource])
    
    return rslt

roles = iam.list_roles()['Roles']

#analyze every policy for every role
count = 0
for role in roles:

    response = iam.list_attached_role_policies(RoleName=role['RoleName'])
    policies = response['AttachedPolicies'] #*****************weakpoint
    graph.add_node( role['RoleName'])
    Role_Security_Threats.append({'RoleName': role['RoleName'], 'Policies': [] })

    for policy in policies:
        policy_name = policy['PolicyName']
        policyReport = {'Policy_Name': policy_name, 'Statement_Report': []} #Each Policy Statement Report
        Arn = iam.get_policy(PolicyArn = policy['PolicyArn'])
        version = Arn['Policy']['DefaultVersionId']
        policyDetails = iam.get_policy_version(PolicyArn = policy['PolicyArn'], VersionId = version)
        graph.add_node(policy_name)
        graph.add_edge(role['RoleName'], policy_name)
        policy_statement =policyDetails['PolicyVersion']['Document']['Statement']

        #Append Analysis of Each Statement to Statement Report List
        policyReport['Statement_Report'].append( analyze(policy_statement, policy_name))
        
    Role_Security_Threats[count]['Policies'].append(policyReport) #Append Policy Report of Every Role
    count +1


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