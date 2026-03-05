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

def analyze( role, statement, rlst):
    
    effect = statement.get('Effect', 'Allow')

    action = statement.get('Action', [])

    if isinstance(action, str):   # if it's just one string
            actions = [action]

    resource = statement.get('Resource', [])

    if isinstance(resource, str):   # if it's just one string
            resources = [resource]

    exempt = False
    for act in actions:
        if 
        if '*' in act
    graph.add_node(policy_name)
    

roles = iam.list_roles()['Roles']

#analyze every policy for every role

for role in roles:
    policies = iam.list_attached_role_policies(RoleName=role_name)
    graph.add_node( role['RoleName'])
    Role_Security_Threats['Role_Analysis'] = {'RoleName': role['RoleName'], 'Policies': [] }
    for policy in policies:
        policy_name = ploicy['PolicyName']
        policyReport = {'Policy_Name': policy_name, 'Statement_Report': []}
        Role_Security_Threats['Role_Analysis']['Policies'].append(policyStmt)
        graph.add_node(policy_name)
        policy_statement = policy['PolicyDocument']['Statement']
        analyze(role['RoleName'],policy_statement, policyReport)


#=====================================================================
# FINDINGS PRINITOUT
#=====================================================================
