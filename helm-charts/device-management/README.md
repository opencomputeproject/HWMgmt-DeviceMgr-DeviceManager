# Nem Monitoring

To deploy this chart please use:

```shell
helm install -n device-management device-management --set images.device_management.pullPolicy='IfNotPresent'  --set images.device_management.tag='latest' --set useCeph=false
```
