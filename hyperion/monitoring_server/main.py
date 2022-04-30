from fastapi import FastAPI, WebSocket
import time
import random

app = FastAPI()

@app.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    cnt = 0
    print("Accepting Connections")
    await websocket.accept()
    print("Accepted Connection")
    while True:
        time.sleep(2)
        cnt+=1
        try:
            # data = await websocket.receive_text()
            print("sending data")
            # await websocket.send_text(f"Sending from server! {cnt}")
            data = {
                "cnt": cnt,
                "a": random.randint(1,5),
                "b": random.randint(1,7)
            }
            await websocket.send_json(data)
            # print("[INFO] Data received: ", data)
        except Exception as e:
            print(f'[Error]: {e}')
            break