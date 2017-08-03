# postgresql dsn (e.g.: postgres://user:password@hostname/database?sslmode=disable) (default: "postgres://localhost/loraserver?sslmode=disable")
#POSTGRES_DSN=postgres://localhost/loraserver?sslmode=disable
./lora-app-server --postgres-dsn postgres://loraserver:dbpassword@localhost/loraserver?sslmode=disable  --http-tls-cert /etc/lora-app-server/certs/http.pem --http-tls-key /etc/lora-app-server/certs/http-key.pem --jwt-secret eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiYXBpcyI6WyIqIl0sImFwcHMiOlsiKiJdLCJub2RlcyI6WyIqIl19.vE4rNylxprgNWNFnAdhXg5AWy5_9F4WfXxOsYRJjg5o

#./lora-app-server --postgres-dsn postgres://localhost/loraserver?sslmode=disable --db-automigrate --migrate-node-sessions  --redis-url redis://localhost:6379 --mqtt-server  tcp://localhost:1883 --bind 0.0.0.0:8001 --http-bind  0.0.0.0:8080

