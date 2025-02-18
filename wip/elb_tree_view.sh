#!/bin/bash
# show where ELBs go
if [[ $# -eq 0 ]]; then echo "Error: Pass profile name"; exit; fi
PROF=$1
account=$(aws --profile ${PROF} sts get-caller-identity | jq -r '.Account')

elb_arns=$(aws --profile ${PROF} elbv2 describe-load-balancers --query "LoadBalancers[].LoadBalancerArn" --output text)
for elb_arn in ${elb_arns[@]}; do 
    target_groups=$(aws --profile ${PROF} elbv2 describe-target-groups --load-balancer-arn ${elb_arn} --query 'TargetGroups[].TargetGroupArn' --output text)
    for tg_arn in ${target_groups[@]}; do
        instances=$(aws --profile ${PROF} elbv2 describe-target-health --target-group-arn ${tg_arn} --query 'TargetHealthDescriptions[*].Target.Id' --output text | tr '\t' ';')
        inst_cnt=$(echo ${instances} | grep -o ';' | wc -l)
        if [[ "${inst_cnt}" -gt 10 ]]; then instances=${inst_cnt}; fi

        ports=$(aws --profile ${PROF} elbv2 describe-listeners --load-balancer-arn ${elb_arn} --query "Listeners[].Port" --output text | sort | tr '\t' ';')
        cert_arns=$(aws --profile ${PROF} elbv2 describe-listeners --load-balancer-arn ${elb_arn} --query "Listeners[].Certificates[].CertificateArn" --output text)
        domains=""
        for cert_arn in ${cert_arns[*]}; do
            domain=$(aws --profile ${PROF} acm describe-certificate --certificate-arn ${cert_arn} --query "Certificate.DomainName" --output text) && domains="${domains};${domain}"
        done

        echo "${account},${ports},${domains},${instances}"
    done
done
