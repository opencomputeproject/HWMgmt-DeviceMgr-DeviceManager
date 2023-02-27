svcs=("svc-account-session" "svc-aggregation" "svc-api" "svc-events" "svc-systems" "svc-task")
port=45101
for svc in ${svcs[@]}; do
  if [ $svc == 'svc-api' ]
  then
     ${svc}/${svc} --registry_address=127.0.0.1:2379 --server_address=127.0.0.1 &
  else
  echo "${svc}/${svc} --registry_address=127.0.0.1:2379 --server_address=127.0.0.1:${port}"
  ${svc}/${svc} --registry_address=127.0.0.1:2379 --server_address=127.0.0.1:${port} &
  ((port=port+1))
  fi
done
