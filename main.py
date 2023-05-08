from fastapi import Depends, FastAPI, HTTPException, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

import paramiko
import os

import auth
import crud
import models
import schemas
from database import SessionLocal, engine

print("We are in the main.......")
if not os.path.exists('.\sqlitedb'):
    print("Making folder.......")
    os.makedirs('.\sqlitedb')

print("Creating tables.......")
models.Base.metadata.create_all(bind=engine)
print("Tables created.......")

app = FastAPI()

# SendGrid configuratie
SENDGRID_API_KEY = "key"
SENDGRID_FROM_EMAIL = "your-email@example.com"

# Instantieer SendGrid-client
sg = SendGridAPIClient(api_key=SENDGRID_API_KEY)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def send_email(to_email: str, subject: str, content: str):
    message = Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=content
    )
    response = sg.send(message)
    return response


def upload_file_to_remote(local_path, remote_path, hostname, port, username, password):
    # maak een SSH-client
    ssh = paramiko.SSHClient()
    # voorkom dat de host key policy wordt gevraagd en accepteer automatisch de sleutel
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # verbind met de remote server met behulp van de opgegeven credentials
    ssh.connect(hostname=hostname, port=port, username=username, password=password)

    # maak een SCP-client
    scp = ssh.open_sftp()
    # upload het bestand naar de remote server
    scp.put(local_path, remote_path)
    # sluit de SCP-client
    scp.close()

    # sluit de SSH-client
    ssh.close()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(
        data={"sub": user.email}
    )
    return {"access_token": access_token, "token_type": "bearer"}


#SCP
@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile = File(...)):
    # upload het bestand naar de remote server
    upload_file_to_remote(file.filename, "/path/to/remote/folder/" + file.filename, "hostname", 22, "username", "password")

    # voeg het bestand toe aan de database
    # db_file = crud.create_file(db=db, file=file)

    return {"filename": file.filename}


#mailsserver
@app.post("/send-email/")
def send_email_handler(to_email: str, subject: str, content: str):
    send_email(to_email, subject, content)
    return {"message": "Email sent"}


#USERS
@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/me", response_model=schemas.User)
def read_users_me(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = auth.get_current_active_user(db, token)
    return current_user


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.post("/users/{user_id}/items/", response_model=schemas.Item)
def create_item_for_user(
    user_id: int, item: schemas.ItemCreate, db: Session = Depends(get_db)
):
    return crud.create_user_item(db=db, item=item, user_id=user_id)


@app.get("/items/", response_model=list[schemas.Item])
def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    items = crud.get_items(db, skip=skip, limit=limit)
    return items

@app.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserUpdate, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    updated_user = crud.update_user(db=db, user=user, db_user=db_user)
    return updated_user


@app.delete("/users/{user_id}/", response_model=schemas.User)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    crud.delete_user(db=db, user_id=user_id)
    return db_user



#FILES
# Upload a file
@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile = File(...)):
    return {"filename": file.filename}

# Update a file
@app.put("/updatefile/{file_id}")
async def update_file(file_id: int, file: UploadFile = File(...)):
    return {"file_id": file_id, "filename": file.filename}

# Delete a file
@app.delete("/deletefile/{file_id}")
async def delete_file(file_id: int):
    return {"file_id": file_id, "status": "deleted"}
