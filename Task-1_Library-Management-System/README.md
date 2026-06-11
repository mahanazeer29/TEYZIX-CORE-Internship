# Library Management System
### Console-Based C++ Application | OOP + File Handling

---

## Overview

A fully featured console-based Library Management System built in C++ using Object-Oriented Programming principles, STL containers, and file-based persistence. Supports admin and member login, complete book/member/borrow management, search, reporting, fine calculation, and CSV export.

---

## Features

### Book Management
- Add, update, delete books
- View all books with availability status
- Auto-generated Book IDs (B1, B2, …)

### Member Management
- Register members with auto-generated IDs (M1, M2, …)
- View all members and active borrow counts
- Full per-member borrow history

### Borrow & Return System
- Issue books with date stamping
- 14-day borrow period
- Return with automatic fine calculation (Rs. 10/overdue day)
- Prevents issuing unavailable books
- Borrow limit: 3 books per member

### Search System
- Search by Book ID (exact)
- Search by Title (partial, case-insensitive)
- Search by Author (partial, case-insensitive)

### Reporting
- Most borrowed books (top 10)
- Currently issued books
- Overdue tracking with fine amounts

### Bonus Features
- **Login system** — Admin and Member roles
- **Fine system** — Rs. 10 per overdue day
- **CSV export** — Books and transactions

---

## Project Structure

```
library_system/
├── main.cpp                  # Entry point & menu UI
├── Makefile
├── include/
│   ├── Book.h
│   ├── Member.h
│   ├── Transaction.h
│   ├── FileHandler.h
│   ├── Library.h
│   ├── Auth.h
│   └── Utils.h
├── src/
│   ├── Book.cpp
│   ├── Member.cpp
│   ├── Transaction.cpp
│   ├── FileHandler.cpp
│   ├── Library.cpp
│   ├── Auth.cpp
│   └── Utils.cpp
└── data/                     # Auto-created at runtime
    ├── books.txt
    ├── members.txt
    ├── transactions.txt
    ├── admin.txt
    ├── books_export.csv
    └── transactions_export.csv
```

---

## OOP Design

| Class | Responsibility |
|---|---|
| `Book` | Encapsulates book data and serialization |
| `Member` | Encapsulates member data and borrow history |
| `Transaction` | Represents a single borrow/return event |
| `Library` | Orchestrates all operations (composition) |
| `FileHandler` | Static file I/O layer (load/save/export) |
| `Auth` | Login system for admin and member roles |
| `Utils` | Shared utilities (dates, input, formatting) |

---

## File Storage Format

**books.txt**
```
B1|The Clean Coder|Robert C. Martin|Programming|1|3
```

**members.txt**
```
M1|Ali Hassan|0321-1234567|1|B1,B3
```

**transactions.txt**
```
TX1|B1|M1|2025-06-01|2025-06-14|1|0.000000
```

---

## Build & Run

### Requirements
- g++ with C++17 support
- Linux / macOS / Windows (MinGW)

### Compile
### Compile
```bash
g++ -std=c++17 -Iinclude main.cpp src/Book.cpp src/Member.cpp src/Transaction.cpp src/FileHandler.cpp src/Library.cpp src/Auth.cpp src/Utils.cpp -o library
```

### Run
```bash
./library
```

---

## Default Admin Login

| Username | Password |
|---|---|
| `admin` | `lib1234` |

Credentials are stored in `data/admin.txt`. You can edit this file to change the password.

---

## Sample Session

```
  ============================================================
               LIBRARY MANAGEMENT SYSTEM
  ============================================================

  Login As:
  [1] Admin
  [2] Member
  [0] Exit
  Choice: 1

  Username: admin
  Password: ****
  Login successful. Welcome, Admin!

  ── Book Management ──────────────
  [1]  Add Book
  [2]  Update Book
  ...
```

---

## Error Handling
- Invalid menu inputs are rejected with re-prompt
- Empty string inputs are blocked
- Issuing an already-issued book is blocked
- Deleting a currently-issued book is blocked
- Members exceeding the 3-book limit are blocked
- Returning a book with no active record is handled

---

## Fine Policy
- Books must be returned within **14 days**
- Fine: **Rs. 10 per overdue day**
- Fine is calculated and displayed on return

---

## CSV Export
Admin can export:
- `data/books_export.csv` — full book catalogue
- `data/transactions_export.csv` — all borrow/return records
