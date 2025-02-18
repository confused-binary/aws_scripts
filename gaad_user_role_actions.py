import json, sys, os

gaad_file_loc = sys.argv[1] if sys.argv[1].endswith('/') else sys.argv[1] + '/'
gaad_files = os.listdir(gaad_file_loc)


def process_users(user_detail_list):
    user_policies = []
    id_type = 'user'
    for user in user_detail_list:
        identity = user.get('UserName')

        # Process Users Inline Policies
        for pol in user.get('UserPolicyList', ''):
            source = 'Inline'
            user_policies = user_policies + process_policy(identity, pol, id_type, source)
        
        # Process User Managed Policies
        for pol in user.get('AttachedManagedPolicies', ''):
            source = 'Managed'
            user_policies = user_policies + process_policy(identity, pol, id_type, source)

        # Process User Groups
        for group_name in user.get('GroupList', ''):
            group_details = [a for a in gaad_details.get('GroupDetailList') if a.get('GroupName') == group_name][0]
            for pol in group_details.get('GroupPolicyList'):
                source = f'Inline_({group_name})'
                user_policies = user_policies + process_policy(identity, pol, id_type, source)
            for pol in group_details.get('AttachedManagedPolicies'):
                source = f'Managed_({group_name})'
                user_policies = user_policies + process_policy(identity, pol, id_type, source)
    return user_policies


def process_roles(role_detail_list):
    role_policies = []
    id_type = 'role'
    for role in role_detail_list:
        identity = role.get('RoleName')

        # Process Role Inline Policies
        for pol in role.get('RolePolicyList', ''):
            source = 'Inline'
            role_policies = role_policies + process_policy(identity, pol, id_type, source)

        # Process Role Managed Policies
        for pol in role.get('AttachedManagedPolicies', ''):
            source = 'Managed'
            role_policies = role_policies + process_policy(identity, pol, id_type, source)
    return role_policies


def process_policy(identity, pol, id_type, source):
    pol_name = pol.get('PolicyName')
    if source.startswith('Managed'):
        pol_arn  = pol.get('PolicyArn')
        pol_details = [a for a in gaad_details.get('Policies') if a.get('Arn') == pol_arn][0]
        pol_doc = [a for a in pol_details.get('PolicyVersionList') if a.get('IsDefaultVersion')][0].get('Document')
    else:
        pol_doc  = pol.get('PolicyDocument')
    return process_statement(account, identity, id_type, source, pol_name, pol_doc)


def process_statement(account, identity, id_type, source, policy_name, pol_doc):
    results = []
    if isinstance(pol_doc.get('Statement'), dict):
        pol_doc['Statement'] = [pol_doc.get('Statement')]
    for statement in pol_doc.get('Statement'):
        effects = [statement.get('Effect')] if isinstance(statement.get('Effect'), str) else statement.get('Effect')
        
        if statement.get('Action'):
            actions = [statement.get('Action')] if isinstance(statement.get('Action'), str) else statement.get('Action')
        elif statement.get('NotAction'):
            not_actions = [statement.get('NotAction')] if isinstance(statement.get('NotAction'), str) else statement.get('NotAction')
            actions = [f"!!!!{a}" for a in not_actions]
        else:
            actions = ['N/A']
        
        if statement.get('Principal'):
            principals = [statement.get('Principal')] if isinstance(statement.get('Principal'), str) else statement.get('Principal')
        elif statement.get('NotPrincipal'):
            not_principals = [statement.get('NotPrincipal')] if isinstance(statement.get('NotPrincipal'), str) else statement.get('NotPrincipal')
            principals = [f"!!!!{a}" for a in not_principals]
        else:
            principals = ['N/A']

        if statement.get('Resource'):
            resources = [statement.get('Resource')] if isinstance(statement.get('Resource'), str) else statement.get('Resource')
        elif statement.get('NotResource'):
            resources = ['N/A']

        if statement.get('Condition'):
            if policy_name == "AWSSSOServiceRolePolicy":
                print()
            condition = statement.get('Condition')
            condition_key = list(condition.keys())[0]
            condition_values = condition.get(condition_key)
            all_condition_data = []
            for key, value in condition_values.items():
                if isinstance(condition_values, dict):
                    condition_data = {
                        'key': condition_key,
                        'nestedKey': key,
                        'nestedValue': value
                    }
                else:
                    condition_data = {}
                all_condition_data.append(condition_data)
        else:
            all_condition_data = [{'key': 'N/A', 'nestedKey': 'N/A', 'nestedValue': 'N/A'}]

        for action in actions:
            for effect in effects:
                for resource in resources:
                    for principal in principals:
                        for condition in all_condition_data:
                            results.append({'account': account,
                                            'identity': identity,
                                            'id_type': id_type,
                                            'source': source,
                                            'policy_name': policy_name,
                                            'principal': principal,
                                            'action': action,
                                            'effect': effect,
                                            'resource': resource,
                                            'conditionKey': condition.get('key'),
                                            'conditionNestedKey': condition.get('nestedKey'),
                                            'conditionNestedValue': condition.get('nestedValue')})
    return results


def print_stuff(exploded_policies):
    print(*[k for k in exploded_policies[0].keys()], sep=',')
    for pol in exploded_policies:
        line = [v for v in pol.values()]
        print(*line, sep=',')

if __name__ == "__main__":
    exploded_policies = []
    for gaad_file in gaad_files:
        # Read GAAD file
        file_stats = os.stat(gaad_file_loc+gaad_file)
        if file_stats.st_size != 0:
            with open(gaad_file_loc+gaad_file, 'r') as file:
                gaad_details = json.load(file)
        else:
            continue

        # infer account from policy ARNs
        for policy in gaad_details.get('Policies'):
            if len(policy.get('Arn').split(':')[4]) == 12:
                account = policy.get('Arn').split(':')[4]
                break
        # print(f"Found file: {gaad_file} ({account})", file=sys.stderr)
        
        # Process Users
        exploded_policies = exploded_policies + process_users(gaad_details.get('UserDetailList',''))
            
        # Process Roles
        exploded_policies = exploded_policies + process_roles(gaad_details.get('RoleDetailList', ''))

    # Print Results
    print_stuff(exploded_policies)
