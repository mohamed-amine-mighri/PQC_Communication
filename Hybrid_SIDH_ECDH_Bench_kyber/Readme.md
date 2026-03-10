Configurer & compiler

cd ../Hybrid_SIDH_ECDH_Masking/
mkdir -p build && cd build
cmake -DUSE_PQSIDH=ON -DSIDH_ROOT=$HOME/PQCrypto-SIDH ..
make -j


# 4.1 Lancer une première fois Bob pour générer sa clé si nécessaire
./bench_tx_bob 127.0.0.1 1883  # (tu peux ^C tout de suite si pas de broker)

# 4.2 Exporter la clé publique DER de Bob depuis sa clé privée
openssl pkey -in ec_local_priv.pem -pubout -outform DER -out bob_pub.der


# Côté Alice :
cp /chemin/vers/bob_pub.der peer_pub.der
# ou spécifie un autre chemin via variable:
export HYB_PEER_PUB_DER=/chemin/vers/bob_pub.der


cd project/build
./bench_tx_bob 192.168.137.8 1883
# Remplace l'IP par celle du broker (127.0.0.1 si local)

cd project/build
# Syntaxe: ./bench_tx_alice <host> <port> <iterations> <sleep_ms>
taskset -c 2 ./bench_tx_alice 192.168.137.8 1883 100 1000



lance un broker Mosquitto (sur la machine choisie)

sudo systemctl enable --now mosquitto
# ou : mosquitto -v


sur Bob (récepteur + ACK + mesure T_unmask)

cd build
# 1er run génère la clé EC locale si absente
./bench_tx_bob 127.0.0.1 1883   # laisse tourner


exporte la pub DER de Bob et donne-la à Alice

# sur la machine où tourne Bob
openssl pkey -in ec_local_priv.pem -pubout -outform DER -out bob_pub.der
# copie ce fichier chez Alice (ou au même endroit si tout est local) :
cp bob_pub.der peer_pub.der


sur Alice (émetteur + mesure T_tx + collecte T_unmask de Bob)

cd build
# (si le fichier n’est pas nommé exactement peer_pub.der, précise le chemin)
# export HYB_PEER_PUB_DER=/chemin/vers/bob_pub.der
taskset -c 2 ./bench_tx_alice 127.0.0.1 1883 100 1000
#                            host  port  iters sleep_ms


Sur la machine de Bob :

openssl pkey -in ec_local_priv.pem -pubout -outform DER -out bob_pub.der
scp bob_pub.der pqcfeten@192.168.137.83:/build/peer_pub.der
cd build
./bench_tx_bob 192.168.137.8 1883


Sur la machine d'alice :
taskset -c 2 ./bench_tx_alice 192.168.137.8 1883 100 1000


python3 ../analyze_bench.py --hybrid results.csv

Workflow bench

Run normal :
./bench_tx_bob_normal 192.168.137.8 1883
taskset -c 2 ./bench_tx_alice_normal 192.168.137.8 1883 100 1000
mv results.csv results_normal.csv

Run hybride :
./bench_tx_bob 192.168.137.8 1883
taskset -c 2 ./bench_tx_alice 192.168.137.8 1883 100 1000
mv results.csv results_hybrid.csv


Analyse comparative :
python3 analyze_bench.py --hybrid results_hybrid.csv --normal results_normal.csv

Benchmarking with kyber: 

Install liboqs (once, on each Pi)

sudo apt-get update
sudo apt-get install -y cmake ninja-build build-essential git libmosquitto-dev
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_ENABLE_KEM_KYBER=ON ..
ninja
sudo ninja install
sudo ldconfig

Start the MQTT broker
sudo systemctl stop mosquitto 2>/dev/null || true
mosquitto -v   # foreground for logs; uses port 1883 by default

Build:

rm -rf build
cmake -S . -B build \
  -DSIDH_ROOT="$SIDH_ROOT" \
  -DUSE_PQSIDH=ON \
  -DUSE_PQSIDH_COMPRESSED=OFF \
  -DUSE_LIBOQS=ON \
  -DBUILD_DEMO=OFF
cmake --build build -j"$(nproc)"


Run: 

Bob (terminal 1) : taskset -c 2 ./bob_kyber_mqtt 192.168.137.8 1883 100 100
Alice (terminal 2) : taskset -c 3 ./alice_kyber_mqtt 192.168.137.8 1883 100 100


rm -rf build
cmake -S . -B build -DSIDH_ROOT=/home/pqcfeten/PQCrypto-SIDH \
      -DUSE_PQSIDH=ON -DUSE_PQSIDH_COMPRESSED=OFF
cmake --build build -j"$(nproc)"

