import json, sys, os

gaad_file_loc = sys.argv[1] if sys.argv[1].endswith('/') else sys.argv[1] + '/'
gaad_files = os.listdir(gaad_file_loc)


def process_roles(role_detail_list):
    role_trust_policies = []
    for role in role_detail_list:
        identity = role.get('RoleName','')
        trust_policy = role.get('AssumeRolePolicyDocument','')
        role_trust_policies = role_trust_policies + process_statement(account, identity, trust_policy)
    return role_trust_policies


def process_statement(account, identity, trust_policy):
    results = []
    for statement in trust_policy.get('Statement'):
        effects = [statement.get('Effect')] if isinstance(statement.get('Effect'), str) else statement.get('Effect')
        
        if statement.get('Action'):
            actions = [statement.get('Action')] if isinstance(statement.get('Action'), str) else statement.get('Action')
        elif statement.get('NotAction'):
            not_actions = [statement.get('NotAction')] if isinstance(statement.get('NotAction'), str) else statement.get('NotAction')
            actions = [f"!!!!{a}" for a in not_actions]
        else:
            actions = ['N/A']
        
        if statement.get('Principal'):
            if isinstance(statement.get('Principal'), dict):
                principals = []
                for p_key, p_val in statement.get('Principal').items():
                    if isinstance(p_val, str):
                        principals.append(statement.get('Principal'))
                    elif isinstance(p_val, list):
                        
                        for val in p_val:
                            if isinstance(val, dict):
                                for nest_key, nest_val in val.items():
                                    principals.append({nest_key, nest_val})
                            elif isinstance(val, str):
                                principals.append({p_key: val})
            else:
                principals = statement.get('Principal')
        elif statement.get('NotPrincipal'):
            not_principals = [statement.get('NotPrincipal')] if isinstance(statement.get('NotPrincipal'), str) else statement.get('NotPrincipal')
            principals = [f"!!!!{a}" for a in not_principals]
        else:
            principals = ['N/A']

        all_condition_data = []
        if statement.get('Condition'):
            for condi_key, cond_values in statement.get('Condition').items():
                for key, value in cond_values.items():
                    if isinstance(cond_values, dict):
                        condition_data = {
                            'key': condi_key,
                            'nestedKey': key,
                            'nestedValue': value
                        }
                    else:
                        condition_data = {}
                    all_condition_data.append(condition_data)
        if not all_condition_data:
            all_condition_data = [{'key': 'N/A', 'nestedKey': 'N/A', 'nestedValue': 'N/A'}]

        for action in actions:
            for effect in effects:
                for principal in principals:
                    for condition in all_condition_data:
                        results.append({'account': account,
                                        'identity': identity,
                                        'principal': list(principal.keys())[0],
                                        'principal_details': list(principal.values())[0],
                                        'action': action,
                                        'effect': effect,
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
        
        # Process Roles
        exploded_policies = exploded_policies + process_roles(gaad_details.get('RoleDetailList', ''))

    # Print Results
    print_stuff(exploded_policies)
