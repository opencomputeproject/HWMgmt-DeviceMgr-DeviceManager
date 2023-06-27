services=("svc-account-session" "svc-aggregation" "svc-api" "svc-events" "svc-task" "svc-systems" "svc-update" "svc-managers")
for service in ${services[@]}; do
  cd "$service"
  go build -o ../apps
  cd ..
done
