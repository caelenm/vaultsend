# VaultSend — build the backend, run the app.
BACKEND := backend/target/release/vaultsend-backend

.PHONY: build run appimage clean

build: $(BACKEND)

$(BACKEND):
	cd backend && cargo build --release

run: build
	python3 frontend/app.py

appimage: build
	cd appimage && ./build-appimage.sh

clean:
	cd backend && cargo clean
	rm -f appimage/VaultSend-x86_64.AppImage appimage/appimagetool
