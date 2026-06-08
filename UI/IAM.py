import boto3
import json
import networkx as nx
from urllib.parse import unquote 

#Script accessing AWS account
iam = boto3.client('iam') 

graph = nx.MultiDiGraph()

Role_Security_Threats = []

def classify_risk(actions, resources, effect, has_condition=False):
    """Single source of truth for statement risk tiering.

    Returns (tier, reason) where tier ∈ {'HIGH', 'MEDIUM', 'LOW', 'DENY'}
    and reason is a short human-readable string that ends up in the
    tooltip on the graph edge.
    """
    # Deny statements are protective, not risky — classify separately.
    if effect == 'Deny':
        return 'DENY', 'Protective Deny statement'

    has_wild_action = any(a == '*' or a.endswith(':*') for a in actions)
    has_wild_resource = any(r == '*' for r in resources)
    has_iam_write = any(
        a == 'iam:*' or (
            a.startswith('iam:') and any(
                verb in a for verb in ('Create', 'Put', 'Attach', 'PassRole', 'Update', 'Delete')
            )
        )
        for a in actions
    )
    has_sts_assume = any('sts:AssumeRole' in a for a in actions)
    has_secret_access = any(
        a.startswith('secretsmanager:') or
        a.startswith('kms:Decrypt') or
        a.startswith('ssm:Get')
        for a in actions
    )

    # HIGH — any single one of these justifies a critical finding.
    if has_wild_action and has_wild_resource:
        return 'HIGH', 'Wildcard action on wildcard resource (root-equivalent access)'
    if has_iam_write and has_wild_resource:
        return 'HIGH', 'IAM mutation on wildcard resource (privilege escalation risk)'
    if has_sts_assume and has_wild_resource:
        return 'HIGH', 'sts:AssumeRole on wildcard resource (account-takeover risk)'
    if has_secret_access and has_wild_resource:
        return 'HIGH', 'Secrets / KMS access on wildcard resource'

    # MEDIUM — worth fixing but not critical danger.
    if has_wild_action:
        return 'MEDIUM', 'Wildcard action on specific resources'
    if has_wild_resource:
        return 'MEDIUM', 'Specific actions on wildcard resource'
    if has_iam_write:
        return 'MEDIUM', 'IAM mutation actions (privilege-escalation potential)'
    if has_sts_assume:
        return 'MEDIUM', 'Cross-account role assumption'
    if len(actions) > 15:
        return 'MEDIUM', f'Excessive scope ({len(actions)} actions in one statement)'

    # LOW — bounded, specific, low blast radius.
    if has_condition:
        return 'LOW', 'Specific actions on specific resources (Condition-constrained)'
    return 'LOW', 'Specific actions on specific resources'


def analyze(statement, policyNode):
    rslt = {'Effect': {}, 'Action': {}, 'Resource': {}, 'Risk': {}, 'RiskReason': {}, 'Description': []}
    if isinstance(statement, dict):
        statement = [statement]

    counter = 1
    for stmt in statement:
        resource_lst = stmt.get('Resource', [])
        action_lst = stmt.get('Action', [])
        # IAM allows scalar string OR list — normalize so downstream code sees a list
        if isinstance(resource_lst, str):
            resource_lst = [resource_lst]
        if isinstance(action_lst, str):
            action_lst = [action_lst]

        effect = stmt.get('Effect', 'Allow')
        has_condition = bool(stmt.get('Condition'))

        rslt['Resource'][counter] = resource_lst
        rslt['Action'][counter] = action_lst
        rslt['Effect'][counter] = effect

        risk, reason = classify_risk(action_lst, resource_lst, effect, has_condition)
        rslt['Risk'][counter] = risk
        rslt['RiskReason'][counter] = reason
        rslt['Description'].append(f'{policyNode}#{counter} → {risk}: {reason}')

        # Graph edge target has to be a single node id — use first resource as representative
        graph_target = resource_lst[0] if resource_lst else '*'
        graph_action = action_lst[0] if action_lst else '*'
        graph.add_edge(policyNode, graph_target, Overall_Risk=risk, Action=graph_action, RiskReason=reason)

        counter = counter + 1
    return rslt

def build_policy_dict(role_security_threats):
    statements = []
    for role in role_security_threats:
        role_name = role['RoleName']
        for policy in role['Policies']:
            policy_name = policy['Policy_Name']
            for stmt_report in policy['Statement_Report']:
                for counter in stmt_report['Effect']:
                    statements.append({
                        'Sid': f'{role_name}__{policy_name}__{counter}',
                        'Effect': stmt_report['Effect'][counter],
                        'Action': stmt_report['Action'][counter],
                        'Resource': stmt_report['Resource'][counter],
                        'Principal': role_name,
                        'Risk': stmt_report['Risk'][counter],
                        'RiskReason': stmt_report['RiskReason'][counter],
                    })
    return {'Version': '2012-10-17', 'Statement': statements}

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
    count += 1

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

policy_dict = build_policy_dict(Role_Security_Threats)
with open("policy_for_js.json", "w") as f:
    json.dump(policy_dict, f, indent=2)
print(f"\n✅ Flattened policy dict written to policy_for_js.json ({len(policy_dict['Statement'])} statements)")

print(f"\n{'=' * 60}")
print(f"\n📊 Identity Graph Summary:")
print(f"   Nodes (roles, policies, resources): {graph.number_of_nodes()}")
print(f"   Edges (permission relationships):   {graph.number_of_edges()}")

graph_json = nx.node_link_data(graph)

with open("graph_export.json", "w") as f:
    json.dump(graph_json, f, indent=2)

print("\n💾 Graph exported to graph_export.json")