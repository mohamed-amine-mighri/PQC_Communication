// transport.h
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <mosquitto.h>

// Connexion simple au broker
struct mosquitto* mqtt_connect_simple(const char* client_id,
                                      const char* host,
                                      int port,
                                      int keepalive);

// Démarre la boucle d’écoute asynchrone
int mqtt_loop_start_simple(struct mosquitto* m);

// Stoppe la boucle
int mqtt_loop_stop_simple(struct mosquitto* m);

// S’abonner à un topic
int mqtt_sub(struct mosquitto* m, const char* topic);

// Publier un message binaire
int mqtt_pub(struct mosquitto* m, const char* topic,
             const void* payload, int len);

// Déconnexion et cleanup
void mqtt_disconnect_simple(struct mosquitto* m);

#endif // TRANSPORT_H
