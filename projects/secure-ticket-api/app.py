"""Secure Ticket API: minimal multi-tenant FastAPI example.

Custom HMAC bearer tokens are for a self-contained local demonstration ONLY.
For real deployments use an audited OIDC/JWT verifier, TLS, a managed DB and rate limits.
"""
from __future__ import annotations
import base64
from contextlib import closing
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value)%4))


def make_demo_token(*, secret: str, sub: str, tenant: str, role: str, expires_at: int) -> str:
    """Create tokens for local tests. Not a replacement for OIDC/JWT."""
    payload=_encode(json.dumps({'sub':sub,'tenant':tenant,'role':role,'exp':expires_at},sort_keys=True,separators=(',',':')).encode())
    signature=_encode(hmac.new(secret.encode(),payload.encode(),hashlib.sha256).digest())
    return payload+'.'+signature


def read_demo_token(token: str, secret: str) -> dict:
    try:
        payload,signature=token.split('.')
        expected=_encode(hmac.new(secret.encode(),payload.encode(),hashlib.sha256).digest())
        if not hmac.compare_digest(expected,signature): raise ValueError('bad signature')
        claims=json.loads(_decode(payload))
        if not isinstance(claims,dict) or not all(isinstance(claims.get(k),str) and claims[k] for k in ('sub','tenant','role')): raise ValueError('bad claims')
        if isinstance(claims.get('exp'),bool) or not isinstance(claims.get('exp'),int) or claims['exp']<=int(time.time()): raise ValueError('expired')
        if claims['role'] not in ('viewer','support'): raise ValueError('bad role')
        return claims
    except (ValueError,UnicodeDecodeError,KeyError,TypeError,json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401,detail='Invalid or expired access token') from exc

class TicketCreate(BaseModel):
    title: str = Field(min_length=4,max_length=120)
    description: str = Field(min_length=0,max_length=1500)

class TicketOut(BaseModel):
    id: str
    tenant: str
    title: str
    description: str
    created_by: str


def create_app(*, database_path: str, token_secret: str) -> FastAPI:
    if len(token_secret)<32: raise ValueError('AUTH_SECRET must contain 32 or more characters')
    app=FastAPI(title='Secure Ticket API (Local Lab)',version='0.1.0',docs_url=None,redoc_url=None)
    def connect():
        conn=sqlite3.connect(database_path,timeout=5)
        conn.row_factory=sqlite3.Row
        return conn
    with closing(connect()) as conn, conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS tickets (
           id TEXT PRIMARY KEY, tenant TEXT NOT NULL, title TEXT NOT NULL,
           description TEXT NOT NULL, created_by TEXT NOT NULL)''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_tickets_tenant ON tickets(tenant)')
    @app.middleware('http')
    async def headers(request: Request,call_next):
        response=await call_next(request)
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='no-referrer'
        return response
    def principal(request:Request)->dict:
        authorization=request.headers.get('authorization','')
        if not authorization.startswith('Bearer '):
            raise HTTPException(status_code=401,detail='Bearer token required')
        return read_demo_token(authorization[len('Bearer '):],token_secret)
    @app.get('/health')
    def health(): return {'status':'ok','service':'secure-ticket-api-local-lab'}
    @app.post('/v1/tickets',response_model=TicketOut,status_code=status.HTTP_201_CREATED)
    def create_ticket(body:TicketCreate,claims:dict=Depends(principal)):
        if claims['role']!='support': raise HTTPException(status_code=403,detail='Insufficient permissions')
        ticket={'id':'TKT-'+uuid.uuid4().hex[:12].upper(),'tenant':claims['tenant'],'title':body.title,'description':body.description,'created_by':claims['sub']}
        with closing(connect()) as conn, conn:
            conn.execute('INSERT INTO tickets (id,tenant,title,description,created_by) VALUES (?,?,?,?,?)',tuple(ticket.values()))
        return ticket
    @app.get('/v1/tickets/{ticket_id}',response_model=TicketOut)
    def get_ticket(ticket_id:str,claims:dict=Depends(principal)):
        # Tenant filter is applied inside SQL. IDs alone never confer access.
        with closing(connect()) as conn:
            row=conn.execute('SELECT id,tenant,title,description,created_by FROM tickets WHERE id = ? AND tenant = ?', (ticket_id,claims['tenant'])).fetchone()
        if row is None: raise HTTPException(status_code=404,detail='Not found')
        return dict(row)
    return app


def main():
    import uvicorn
    secret=os.environ.get('AUTH_SECRET','')
    app=create_app(database_path=os.environ.get('DATABASE_PATH','local-tickets.sqlite3'),token_secret=secret)
    uvicorn.run(app,host='127.0.0.1',port=8081,log_level='info')
if __name__=='__main__': main()
