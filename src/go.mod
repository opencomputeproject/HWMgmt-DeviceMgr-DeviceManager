module devicemanager

go 1.13

require (
	github.com/ODIM-Project/ODIM/lib-utilities v0.0.0-20220905064038-7d38588674bd
	github.com/ODIM-Project/ODIM/lib-dmtf v0.0.0-00010101000000-000000000000
	github.com/Shopify/sarama v1.28.0
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.3.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/kataras/iris/v12 v12.2.0-alpha9
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	google.golang.org/grpc v1.38.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

require (
	github.com/dgraph-io/badger v1.6.0 // indirect
	github.com/etcd-io/bbolt v1.3.3 // indirect
	github.com/gavv/httpexpect v2.0.0+incompatible // indirect
	github.com/magefile/mage v1.10.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace (
	github.com/ODIM-Project/ODIM/lib-dmtf => ../lib-dmtf
	github.com/ODIM-Project/ODIM/lib-utilities => ../lib-utilities
	github.com/ODIM-Project/ODIM/lib-persistence-manager => ../lib-persistence-manager
)
