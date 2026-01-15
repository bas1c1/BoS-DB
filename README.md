AUTH (формат пароля - base64):
```
AUTH <user> <password>
```
Ответ:
```
OK <token>
```


SET:
```
SET <токен> mykey myvalue
```
Ответ:
```
OK
```


GET:
```
GET <токен> mykey
```
Ответ:
```
myvalue
```


CREATE_USER (только для администратора):
```
CREATE_USER <токен_админа> newuser password
```
Ответа нет, происходит переподключение



Пример подключения с помощью openssl s_client:
```
openssl s_client -connect localhost:6379 -tls1_3
```


Запуск СУБД:

```
docker run -d \
  --name bos-db \
  --read-only \
  --tmpfs /tmp:rw,size=1M,uid=65532,gid=65532,mode=1700 \
  --tmpfs /run:rw,size=512k,uid=65532,gid=65532,mode=1700 \
  --tmpfs /.bos_db:rw,size=10M,uid=65532,gid=65532,mode=700 \
  --cap-drop=ALL \
  --memory=64m \
  --cpus=0.5 \
  --pids-limit=16 \
  --network none \
  -p 127.0.0.1:6379:6379 \
  --restart unless-stopped \
  bos-db
```