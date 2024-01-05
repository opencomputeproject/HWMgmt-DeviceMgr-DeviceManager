services=("svc-account-session" "svc-aggregation" "svc-api" "svc-events" "svc-task" "svc-systems" "svc-update" "svc-managers" "svc-telemetry")
for service in ${services[@]}; do
  cd "$service"
  $GOROOT/bin/go build -o ../apps
  cd ..
done
