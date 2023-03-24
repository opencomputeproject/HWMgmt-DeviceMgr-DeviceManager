#!/usr/bin/env bash

svcs=("svc-account-session" "svc-aggregation" "svc-api" "svc-events" "svc-systems" "svc-task")
port=45101
for svc in ${svcs[@]}; do
  if [ $svc == 'svc-api' ]
  then
     ${svc} --registry_address=etcd:2379 --server_address=127.0.0.1 >> /var/log/deviceManager/${svc}.log 2>&1 &
  else
  echo "${svc} --registry_address=etcd:2379 --server_address=127.0.0.1:${port}"
  ${svc} --registry_address=etcd:2379 --server_address=127.0.0.1:${port} >> /var/log/deviceManager/${svc}.log 2>&1 &
  ((port=port+1))
  fi
done

wait
