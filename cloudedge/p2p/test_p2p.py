import time
import logging

# Adatta l'import al nome del file/classe del tuo client
from client import Client 
from cloudedge.p2p.p2p_streamer import P2PStreamer

logging.basicConfig(level=logging.DEBUG)

def on_video(frame):
    print(f"SUCCESS: Frame VIDEO ricevuto! ({len(frame)} byte)")

def on_audio(frame):
    print(f"Frame AUDIO ricevuto! ({len(frame)} byte)")

def main():
    # 1. Login con le tue credenziali
    client = Client("TUO_UTENTE", "TUA_PASSWORD")
    client.login()

    # 2. Recupera la prima telecamera ("Cancelletto")
    devices = client.get_all_devices()
    target_device = devices[0]
    print(f"Tentativo di connessione a: {target_device}")

    # 3. Inizializza ed esegui lo streamer
    streamer = P2PStreamer(
        api=client,
        device=target_device,
        on_video=on_video,
        on_audio=on_audio
    )

    print("Avvio sessione P2P...")
    streamer.run_session()

    # Lascia girare il test per 20 secondi
    time.sleep(20)

if __name__ == "__main__":
    main()
