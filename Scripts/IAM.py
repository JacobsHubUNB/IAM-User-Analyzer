import boto3
import json
import networkx as nx
from urllib.parse import unquote 

#Script accessing AWS account
iam = boto3.client('iam') 

graph = nx.DiGraph()

#list containing the security threats of each resource for every policy for every role

security_threats = []

#=====================================================================
# DATA EXTRACTION AND PROCESSING
#=====================================================================

def analyze(policy_doc, policies):

    graph.add_node(policy_name)

roles = iam.list_roles()['Roles']

#analyze every policy for every role

for role in roles:
    role_name = role['Rolename']
    policies = iam.list_attached_role_policies(RoleName=role_name)
    policydict = role['AssumeRolePolicyDocument']
    policy_names = role['AttachedPolicies']
    graph.add_node(role_name)
    analyze(policydict,policies )

#=====================================================================
# FINDING PRINITOUT
#=====================================================================
