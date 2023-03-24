protos=("account" "aggregator" "auth" "chassis" "events" "fabrics" "managers" "role" "session" "systems" "task" "telemetry" "update" "compositionservice")
path="$(pwd)/lib-utilities/proto"
for str in ${protos[@]}; do
  proto_path="$path/$str"
  proto_file_name="$str.proto"
  if [ $str == 'auth' ]
  then
    proto_file_name="odim_auth.proto"
  fi
  if [ $str == 'compositionservice' ]
    then
      proto_file_name="composition_service.proto"
    fi
  protoc --go_opt=M$proto_file_name=./ --go_out=plugins=grpc:$proto_path --proto_path=$proto_path $proto_file_name
done
