mkdir ${ENG_HOME}/docker_gitleaks_results/
while true; do
    if [[ "$(wc -l ./gitleaks_scan_me | cut -d' ' -f1)" > 0 ]]; then 
        for unpack_dir in $(head -1 ./gitleaks_scan_me); do
            echo "scanning: ${unpack_dir}"
            gitleaks detect --source ./${unpack_dir} --no-git --verbose &> ${ENG_HOME}/docker_gitleaks_results/${unpack_dir}
            echo "cleanup: ${unpack_dir}"
            sed -i "/${unpack_dir}/d" ./gitleaks_scan_me
            rm -Rf ./${unpack_dir}
        done
    fi
    [[ "$(wc -l ./gitleaks_scan_me | cut -d' ' -f1)" == 0 ]] && echo "Nothing to scan atm"
    sleep 5
done