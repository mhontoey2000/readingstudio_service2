# ใช้ node:latest เป็นฐานของ Docker image
FROM node:latest

# ติดตั้งแพ็คเกจ mysql2 โดยใช้ npm
RUN npm install mysql2

# สร้างโฟลเดอร์ app และตั้งค่าเป็นโฟลเดอร์ปัจจุบัน
WORKDIR /app

# คัดลอกไฟล์ package.json และ package-lock.json ไปยังโฟลเดอร์ app
COPY package*.json ./

# ติดตั้ง dependencies ของแอปพลิเคชัน
RUN npm install

# คัดลอกโค้ดของแอปพลิเคชันไปยังโฟลเดอร์ app
COPY . .

# แอพพลิเคชันจะทำงานที่พอร์ต 3000
EXPOSE 3000

# คำสั่งเริ่มต้นของแอพพลิเคชัน
CMD ["node", "index.js"]
