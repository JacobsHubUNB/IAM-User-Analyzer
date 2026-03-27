import boto3
import json
import networkx as nx
from urllib.parse import unquote 

#Script accessing AWS account
iam = boto3.client('iam') 

graph = nx.MultiGraph()

Role_Security_Threats = []

def analyze(statement, policyNode):
    rslt = {'Effect': '', 'Action': '', 'Resource': '', 'Risk': '', 'Description': ''}
    if isinstance(statement, dict):
        statement = [statement]
    
    rslt['Effect'] = {}
    rslt['Action'] = {}
    rslt['Resource'] = {}
    rslt['Risk'] = {}
    rslt['Description'] = []
    counter = 1
    for stmt in statement:
        resource_lst = stmt.get('Resource', [])
        action_lst = stmt.get('Action', [])

        rslt['Resource'][counter] = resource_lst[0]
        rslt['Action'] [counter]= action_lst[0]
        rslt['Effect'][counter] = stmt.get('Effect','Allow')
        rslt['Risk'][counter] = ''

        if '*' in rslt['Action'][counter] or len(action_lst) >4:
            rslt['Risk'][counter] = "MEDIUM"
            rslt['Description'].append("Warning, Wildcard Action Detected")
        elif len(resource_lst) < 5 and len(action_lst) > 2:
            rslt['Risk'][counter] = 'MEDIUM'
            rslt['Description'].append('Too many Permissions, Simplify And Specialize Role')
        else:
                rslt['Risk'][counter] = 'LOW'


        if '*' in rslt['Resource'][counter] and 'MEDIUM' in rslt['Risk'][counter]:
            rslt['Risk'][counter] = "HIGH"
            rslt['Description'].append('\nCritical, Wildcard Resorces AND Action Detected!')
        elif '*' in rslt['Resource'][counter] or 'MEDIUM' in  rslt['Risk'][counter] :
                rslt['Risk'][counter] = "MEDIUM"
                rslt['Description'].append("\nWarning Role Contains Wildcard Resource or Action")
        else:
            rslt['Risk'][counter] = "LOW"
            rslt['Description'].append("Role Obeys Law of Least Resource/Action Privillage")

        graph.add_edge(policyNode,  rslt['Resource'][counter], Overall_Risk = rslt['Risk'][counter], Action = rslt['Action'][counter]) # Number of actions used instead of explicit action list to keep things simple
    
        counter = counter +1
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
        print(json.dumps(policy['Statement_Report'], indent = 4))


print(f"\n{'=' * 60}")
print(f"\n📊 Identity Graph Summary:")
print(f"   Nodes (roles, policies, resources): {graph.number_of_nodes()}")
print(f"   Edges (permission relationships):   {graph.number_of_edges()}")

graph_json = nx.node_link_data(graph)

with open("graph_export.json", "w") as f:
    json.dump(graph_json, f, indent=2)

print("\n💾 Graph exported to graph_export.json")