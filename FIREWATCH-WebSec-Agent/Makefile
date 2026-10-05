.PHONY: backend frontend test demo

backend:
	cd backend && uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

frontend:
	cd frontend && npm run dev

test:
	cd backend && pytest -q

demo:
	cd demo_target && uvicorn main:app --host 127.0.0.1 --port 9000
