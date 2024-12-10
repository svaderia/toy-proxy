`gcc -o proxy proxy.c -levent`

Make sure you have libevent installed, see setup_pgboring.sh in the emulab
script project otherwise.

Change the benchbase config file to point to correct port

Change the hardcodec values for database as you want.

The code is very inspired with chattg, so it has some weird comments that I
haven't cleaned up.

It tries to do some sort of transaction pooling, though if we don't have enough
server it would reject clients.

Please add following in the bechnbase config if you use it:
```xml
    <url>jdbc:postgresql://pgb:6432/benchbase?sslmode=disable&amp;ApplicationName=tpcc&amp;reWriteBatchedInserts=true&amp;preferQueryMode=simple</url>
```

`preferQueryMode=simple` ensures that the client doesn't use extended wire
protocol. 


You should see some form on UTF-8 error.
