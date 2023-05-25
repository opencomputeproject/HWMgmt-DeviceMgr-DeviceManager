#!/usr/bin/env bash

svcs=("svc-account-session" "svc-aggregation" "svc-api" "svc-events" "svc-systems" "svc-task" "svc-update" "svc-managers")
port=45101
for svc in ${svcs[@]}; do
  if [ $svc == 'svc-api' ]
  then
     ${svc} --registry_address=etcd:2379 --server_address=device-manager >> /var/log/deviceManager/${svc}.log 2>&1 &
  else
  echo "${svc} --registry_address=etcd:2379 --server_address=device-manager:${port}"
  ${svc} --registry_address=etcd:2379 --server_address=device-manager:${port} >> /var/log/deviceManager/${svc}.log 2>&1 &
  ((port=port+1))
  if [ $svc == 'svc-task' ]
  then
    ((port=port+1))
  fi
  fi
done

svc-device-manager >> /var/log/deviceManager/svc-device-manager.log 2>&1 &

wait
