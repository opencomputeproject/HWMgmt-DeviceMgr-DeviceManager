services=("svc-account-session" "svc-aggregation" "svc-api" "svc-events" "svc-task" "svc-systems")
for service in ${services[@]}; do
  cd "$service"
  go build -o ../apps
  cd ..
done
