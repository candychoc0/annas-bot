# annas-bot

A Telegram bot that lets you search and download books in EPUB format from Anna's Archive, available in French and English.


## Features

- Search books by title or author via Anna's Archive
- Download books directly in Telegram (EPUB or PDF)
- Torrent support via Prowlarr
- French and English interface
- Fully containerized with Docker


## Technologies

- **Python 3.12**
- **python-telegram-bot** — Telegram bot framework
- **Docker & Docker Compose** — containerization
- **Prowlarr** — torrent indexer manager
- **qBittorrent** — torrent download client
- **httpx** — async HTTP requests
- **BeautifulSoup** — HTML scraping

## Prerequisites

- Docker and Docker Compose 
- A Telegram account
- Git 

## Setup

### 1. Clone the repo

git clone https://github.com/candychoc0/annas-bot.git
cd annas-bot

### 2. Configure environment

cp .env.example .env

Edit `.env` and fill in your values:

TELEGRAM_TOKEN=your_token_from_botfather
ALLOWED_USER_IDS=your_telegram_id
ANNA_ARCHIVE_URL=https://annas-archive.gl
PROWLARR_URL=http://prowlarr:9696
PROWLARR_API_KEY=your_prowlarr_api_key
BOOKS_DOWNLOAD_PATH=/downloads
ALLOWED_FORMATS=epub,pdf

### 3. Start

docker compose up -d
