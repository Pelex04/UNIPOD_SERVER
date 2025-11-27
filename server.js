const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const cors = require("cors");
const bcrypt = require("bcrypt");
require('dotenv').config();


const app = express();
const port = 3000;
app.use(cors()); 


app.use(express.json());

let db;
try {
  db = new sqlite3.Database("unipod.db", (err) => {
    if (err) {
      console.error("Error opening database:", err.message);
    } else {
      console.log("Connected to the SQLite database.");
    }
  });
} catch (e) {
  console.error("Failed to initialize database:", e.message);
  process.exit(1);
}

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      userid TEXT NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      arrival_time TEXT NOT NULL,
      exit_time TEXT,
      FOREIGN KEY (email) REFERENCES users (email)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      email TEXT PRIMARY KEY,
      expires TEXT,
      hours_remaining INTEGER,
      FOREIGN KEY (email) REFERENCES users (email)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS payments (
      transaction_id TEXT PRIMARY KEY,
      charge_id TEXT,
      email TEXT NOT NULL,
      amount INTEGER NOT NULL,
      currency TEXT NOT NULL,
      method TEXT NOT NULL,
      status TEXT NOT NULL,
      card_type TEXT,
      card_last4 TEXT,
      phone_number TEXT,
      payment_date TEXT NOT NULL,
      message TEXT,
      trans_id TEXT,
      ref_id TEXT,
      FOREIGN KEY (email) REFERENCES users (email)
    )
  `);

  db.run(`ALTER TABLE users ADD COLUMN password TEXT`, (err) => {
    if (err && !err.message.includes("duplicate column name")) {
      console.error("Error adding password column:", err.message);
    } else {
      console.log("Password column handled");
    }
  });

  db.run(`ALTER TABLE payments ADD COLUMN trans_id TEXT`, (err) => {
    if (err && !err.message.includes("duplicate column name")) {
      console.error("Error adding trans_id column:", err.message);
    } else {
      console.log("Added trans_id column to payments table");
    }
  });
  db.run(`ALTER TABLE payments ADD COLUMN ref_id TEXT`, (err) => {
    if (err && !err.message.includes("duplicate column name")) {
      console.error("Error adding ref_id column:", err.message);
    } else {
      console.log("Added ref_id column to payments table");
    }
  });

  db.get("SELECT COUNT(*) AS count FROM users", (err, row) => {
    if (err) {
      console.error("Error checking users table:", err.message);
    } else if (row.count === 0) {
      console.log("Inserting sample user data...");

      bcrypt.hash("password123", 10, (err, hash1) => {
        if (err) {
          console.error("Error hashing password:", err);
          return;
        }
        bcrypt.hash("admin123", 10, (err, hash2) => {
          if (err) {
            console.error("Error hashing password:", err);
            return;
          }
          db.run(
            `
            INSERT INTO users (email, name, userid, password) VALUES
            ('test@example.com', 'Test User', 'QR12345', ?),
            ('admin@mubas.edu', 'Admin User', 'QRADMIN', ?)
          `,
            [hash1, hash2],
            (err) => {
              if (err) {
                console.error("Error inserting sample data:", err.message);
              } else {
                console.log("Sample data inserted successfully.");
              }
            }
          );
        });
      });

      db.run(
        `
        INSERT INTO sessions (email, arrival_time, exit_time) VALUES
        ('test@example.com', '2025-09-20T08:00:00Z', '2025-09-20T10:00:00Z'),
        ('test@example.com', '2025-09-21T09:00:00Z', NULL)
      `,
        (err) => {
          if (err) {
            console.error("Error inserting sample data:", err.message);
          } else {
            console.log("Sample sessions inserted successfully.");
          }
        }
      );
    }
  });
});

const paychanguSecretKey = process.env.PAYCHANGU_SECRET_KEY;


let supportedOperators = null;

async function fetchSupportedOperators() {
  if (supportedOperators) return supportedOperators;

  try {
    const { default: fetch } = await import("node-fetch");
    const response = await fetch("https://api.paychangu.com/mobile-money", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${paychanguSecretKey}`,
        Accept: "application/json",
      },
    });

    const data = await response.json();
    if (response.ok && data.status === "success") {
      supportedOperators = data.data || [];
      console.log("Fetched supported operators:", supportedOperators);
      return supportedOperators;
    } else {
      console.error("Failed to fetch operators:", data);
      return null;
    }
  } catch (e) {
    console.error("Error fetching operators:", e.message);
    return null;
  }
}

function getOperatorRefId(operatorName) {
  const operators = supportedOperators || [
    { name: "Airtel Money", ref_id: "20be6c20-adeb-4b5b-a7ba-0769820df4fb" },
    { name: "TNM Mpamba", ref_id: "27494cb5-ba9e-437f-a114-4e7a7686bcca" },
  ];

  const operator = operators.find((op) =>
    op.name.toLowerCase().includes(operatorName.toLowerCase())
  );
  return operator ? operator.ref_id : null;
}

app.post("/api/register", async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res
      .status(400)
      .json({ error: "Email, password, and name are required" });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters long" });
  }

  db.get(
    "SELECT email FROM users WHERE email = ?",
    [email],
    async (err, user) => {
      if (err) {
        console.error("Database error:", err.message);
        return res.status(500).json({ error: "Database error" });
      }

      if (user) {
        return res
          .status(400)
          .json({ error: "User already exists with this email" });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const userid = `QR${Date.now()}${Math.floor(Math.random() * 1000)}`;

        db.run(
          "INSERT INTO users (email, name, userid, password) VALUES (?, ?, ?, ?)",
          [email, name, userid, hashedPassword],
          function (err) {
            if (err) {
              console.error("Error creating user:", err.message);
              return res.status(500).json({ error: "Failed to create user" });
            }
            console.log(`User created: ${email}`);
            res
              .status(201)
              .json({
                success: true,
                message: "User registered successfully",
                userid: userid,
              });
          }
        );
      } catch (hashError) {
        console.error("Password hashing error:", hashError);
        res.status(500).json({ error: "Failed to hash password" });
      }
    }
  );
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) {
      console.error("Database error:", err.message);
      return res.status(500).json({ error: "Database error" });
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error("Password comparison error:", err.message);
        return res.status(500).json({ error: "Server error" });
      }

      if (result) {
        db.get(
          `
          SELECT s.id, s.arrival_time AS ArrivalTime, s.exit_time AS ExitTime
          FROM sessions s
          WHERE s.email = ? AND s.exit_time IS NULL
        `,
          [email],
          (err, session) => {
            if (err) {
              console.error("Session fetch error:", err.message);
              return res
                .status(500)
                .json({ error: "Failed to fetch session data" });
            }

            res.json({
              success: true,
              user: {
                Email: user.email,
                Name: user.name,
                userid: user.userid,
                ...(session || {}),
              },
            });
          }
        );
      } else {
        res.status(401).json({ error: "Invalid email or password" });
      }
    });
  });
});

app.get("/api/getESP", (req, res) => {
  const query = `
    SELECT 
      u.email AS Email,
      u.name AS Name,
      u.userid AS userid,
      s.id AS id,
      s.arrival_time AS ArrivalTime,
      s.exit_time AS ExitTime
    FROM users u
    LEFT JOIN sessions s ON u.email = s.email AND s.exit_time IS NULL
  `;
  db.all(query, (err, rows) => {
    if (err) {
      console.error("Error fetching data:", err.message);
      return res.status(500).json({ error: "Failed to fetch data" });
    }
    res.json({
      total: rows.length,
      documents: rows,
    });
  });
});

app.post("/api/updateESP", (req, res) => {
  const { Email, id, ArrivalTime, ExitTime } = req.body;

  if (!Email) {
    return res.status(400).json({ error: "Email is required" });
  }

  if (id) {
    if (!ExitTime) {
      return res
        .status(400)
        .json({ error: "ExitTime is required for updates" });
    }
    db.run(
      "UPDATE sessions SET exit_time = ? WHERE id = ? AND email = ?",
      [ExitTime, id, Email],
      function (err) {
        if (err) {
          console.error("Error updating session:", err.message);
          return res.status(500).json({ error: "Failed to update session" });
        }
        if (this.changes === 0) {
          return res.status(404).json({
            error: "Session not found or does not belong to this email",
          });
        }
        res.status(200).json({ message: "Session updated successfully" });
      }
    );
  } else {
    if (!ArrivalTime) {
      return res
        .status(400)
        .json({ error: "ArrivalTime is required for new sessions" });
    }
    db.get("SELECT * FROM users WHERE email = ?", [Email], (err, user) => {
      if (err) {
        console.error("Error checking user:", err.message);
        return res.status(500).json({ error: "Failed to check user" });
      }
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      db.get(
        "SELECT * FROM sessions WHERE email = ? AND exit_time IS NULL",
        [Email],
        (err, openSession) => {
          if (err) {
            console.error("Error checking open session:", err.message);
            return res
              .status(500)
              .json({ error: "Failed to check open session" });
          }
          if (openSession) {
            return res
              .status(400)
              .json({ error: "User already has an open session" });
          }
          db.run(
            "INSERT INTO sessions (email, arrival_time) VALUES (?, ?)",
            [Email, ArrivalTime],
            (err) => {
              if (err) {
                console.error("Error creating session:", err.message);
                return res
                  .status(500)
                  .json({ error: "Failed to create session" });
              }
              res.status(200).json({ message: "Session created successfully" });
            }
          );
        }
      );
    });
  }
});

app.get("/api/history", (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const query = `
    SELECT 
      id,
      email AS Email,
      arrival_time AS ArrivalTime,
      exit_time AS ExitTime
    FROM sessions
    WHERE email = ?
    ORDER BY arrival_time DESC
  `;
  db.all(query, [email], (err, rows) => {
    if (err) {
      console.error("Error fetching history:", err.message);
      return res.status(500).json({ error: "Failed to fetch history" });
    }
    res.json({
      total: rows.length,
      sessions: rows,
    });
  });
});

app.get("/api/hours", (req, res) => {
  const { email, period = "week" } = req.query;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  let startDate, endDate;
  const today = new Date();

  if (period === "month") {
    startDate = new Date(today.getFullYear(), today.getMonth(), 1);
    endDate = new Date(today.getFullYear(), today.getMonth() + 1, 0);
  } else {
    const dayOfWeek = today.getDay();
    startDate = new Date(today);
    startDate.setDate(today.getDate() - dayOfWeek);
    startDate.setHours(0, 0, 0, 0);
    endDate = new Date(startDate);
    endDate.setDate(startDate.getDate() + 7);
  }

  startDate.setHours(0, 0, 0, 0);
  endDate.setHours(23, 59, 59, 999);

  const query = `
    SELECT arrival_time, exit_time
    FROM sessions
    WHERE email = ? AND exit_time IS NOT NULL
    AND arrival_time >= ? AND arrival_time <= ?
  `;
  db.all(
    query,
    [email, startDate.toISOString(), endDate.toISOString()],
    (err, rows) => {
      if (err) {
        console.error("Error fetching hours:", err.message);
        return res.status(500).json({ error: "Failed to fetch hours" });
      }

      let totalMinutes = 0;
      rows.forEach((session) => {
        const start = new Date(session.arrival_time);
        const end = new Date(session.exit_time);
        const duration = (end - start) / (1000 * 60);
        totalMinutes += duration;
      });

      const hours = Math.floor(totalMinutes / 60);
      const minutes = Math.round(totalMinutes % 60);

      res.json({
        totalHours: hours,
        totalMinutes: minutes,
        period: period,
      });
    }
  );
});

app.post("/api/process-payment", async (req, res) => {
  const {
    amount,
    currency,
    email,
    method,
    transaction_id,
    card_details,
    phone_number,
  } = req.body;

  if (!amount || !currency || !email || !method || !transaction_id) {
    return res.status(400).json({
      error: "Amount, currency, email, method, and transaction_id are required",
    });
  }

  if (
    method === "Card" &&
    (!card_details ||
      !card_details.card_number ||
      !card_details.card_holder ||
      !card_details.expiry ||
      !card_details.cvv)
  ) {
    return res
      .status(400)
      .json({ error: "Card details are required for card payments" });
  }

  if ((method === "Airtel Money" || method === "Mpamba") && !phone_number) {
    return res
      .status(400)
      .json({ error: "Phone number is required for mobile money payments" });
  }

  const paymentDate = new Date().toISOString();

  try {
    const { default: fetch } = await import("node-fetch");

    let apiResponse;
    let chargeId;
    let status = "pending";
    let message = "Payment initiated";
    let requires3ds = false;
    let threeDsUrl;

    if (method === "Card") {
      const cardNumber = card_details.card_number.replace(/\s/g, "");
      if (!/^\d{13,19}$/.test(cardNumber)) {
        return res.status(400).json({ error: "Invalid card number format" });
      }
      const [expiryMonth, expiryYear] = card_details.expiry.split("/");
      if (!/^\d{2}$/.test(expiryMonth) || !/^\d{2,4}$/.test(expiryYear)) {
        return res
          .status(400)
          .json({ error: "Invalid expiry date format (MM/YY or MM/YYYY)" });
      }

      const payload = {
        card_number: cardNumber,
        expiry: card_details.expiry,
        cvv: card_details.cvv,
        cardholder_name: card_details.card_holder,
        amount: parseInt(amount),
        currency: currency,
        email: email,
        charge_id: transaction_id,
        redirect_url: "https://58dc3832780e.ngrok-free.app/return",
      };

      console.log("Card Payment Payload:", JSON.stringify(payload, null, 2));
      apiResponse = await fetch(
        "https://api.paychangu.com/charge-card/payments",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${paychanguSecretKey}`,
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      const data = await apiResponse.json();
      console.log("Card Payment Response:", JSON.stringify(data, null, 2));

      if (!apiResponse.ok) {
        throw new Error(data.error || "Card charge failed");
      }

      chargeId = data.orderReference || transaction_id;
      if (data.requires_3ds_auth) {
        requires3ds = true;
        threeDsUrl = data["3ds_auth_link"];
        message = "3DS authentication required";
        status = "pending";
      } else {
        const verifyData = await _verifyCardCharge(chargeId);
        status = verifyData.status === "success" ? "success" : "failed";
        message = verifyData.message || "Payment processed";
      }
    } else {
      await fetchSupportedOperators();
      const operatorName =
        method === "Airtel Money" ? "Airtel Money" : "TNM Mpamba";
      const mobileMoneyOperatorRefId = getOperatorRefId(operatorName);
      if (!mobileMoneyOperatorRefId) {
        throw new Error(`Operator ref_id not found for ${operatorName}`);
      }

      const payload = {
        mobile_money_operator_ref_id: mobileMoneyOperatorRefId,
        amount: amount,
        currency: currency,
        mobile: phone_number.replace("+265", "0"),
        charge_id: transaction_id,
        reference: transaction_id,
        email: email,
      };
      console.log("Mobile Money Payload:", JSON.stringify(payload, null, 2));

      apiResponse = await fetch(
        "https://api.paychangu.com/mobile-money/payments/initialize",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${paychanguSecretKey}`,
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      const data = await apiResponse.json();
      console.log("Mobile Money Response:", JSON.stringify(data, null, 2));

      if (!apiResponse.ok) {
        throw new Error(data.message || "Mobile money charge failed");
      }

      chargeId = data.charge_id || transaction_id;
      message = "Payment initiated, please authorize on your phone";
    }

    db.run(
      `INSERT INTO payments (transaction_id, charge_id, email, amount, currency, method, status, card_type, card_last4, phone_number, payment_date, message)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        transaction_id,
        chargeId,
        email,
        amount,
        currency,
        method,
        status,
        card_details?.card_type || null,
        card_details?.card_last4 || null,
        phone_number || null,
        paymentDate,
        message,
      ],
      (err) => {
        if (err) {
          console.error("Error logging payment:", err.message);
        }
      }
    );

    res.json({
      success: true,
      transaction_id: transaction_id,
      charge_id: chargeId,
      status: status,
      amount: amount,
      timestamp: paymentDate,
      message: message,
      requires_3ds: requires3ds,
      threeDsUrl: threeDsUrl,
    });

    if (status === "success") {
      _updateSubscription(email, paymentDate);
    }
  } catch (e) {
    console.error("Error processing payment:", e.message, e.stack);
    res.status(500).json({ error: `Failed to process payment: ${e.message}` });
  }
});

async function _verifyCardCharge(chargeId) {
  const response = await fetch(
    `https://api.paychangu.com/charge-card/verify/${chargeId}`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${paychanguSecretKey}`,
        Accept: "application/json",
      },
    }
  );

  const data = await response.json();
  return data;
}

app.get("/api/verify-payment", async (req, res) => {
  const { charge_id, tx_ref } = req.query;

  if (!charge_id || !tx_ref) {
    return res.status(400).json({ error: "charge_id and tx_ref are required" });
  }

  try {
    return new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM payments WHERE transaction_id = ?",
        [tx_ref],
        async (err, payment) => {
          if (err) {
            console.error("Database error fetching payment:", err.message);
            return reject(new Error("Database error"));
          }
          if (!payment) {
            return res.status(404).json({ error: "Payment not found" });
          }

          if (payment.status === "success" || payment.status === "failed") {
            res.json({
              status: payment.status,
              message: payment.message || "Payment successful",
              trans_id: payment.trans_id,
              ref_id: payment.ref_id,
            });
            return resolve();
          }

          let apiResponse;
          try {
            if (payment.method === "Card") {
              apiResponse = await fetch(
                `https://api.paychangu.com/charge-card/verify/${charge_id}`,
                {
                  method: "GET",
                  headers: {
                    Authorization: `Bearer ${paychanguSecretKey}`,
                    Accept: "application/json",
                  },
                }
              );
            } else {
              apiResponse = await fetch(
                `https://api.paychangu.com/mobile-money/payments/${charge_id}/verify`,
                {
                  method: "GET",
                  headers: {
                    Authorization: `Bearer ${paychanguSecretKey}`,
                    Accept: "application/json",
                  },
                }
              );
            }

            const data = await apiResponse.json();
            console.log(
              "Verification API Response:",
              JSON.stringify(data, null, 2)
            );

            if (apiResponse.ok) {
              const status =
                data.status === "success" || data.status === "successful"
                  ? "success"
                  : "failed";
              const message =
                data.message && data.message.toLowerCase().includes("already")
                  ? "Payment successful"
                  : data.message || "Payment successful";
              db.run(
                `UPDATE payments SET status = ?, message = ?, trans_id = ?, ref_id = ? WHERE transaction_id = ?`,
                [
                  status,
                  message,
                  data.data?.trans_id || null,
                  data.data?.ref_id || null,
                  tx_ref,
                ],
                (err) => {
                  if (err)
                    console.error(
                      "Error updating payment status:",
                      err.message
                    );
                }
              );
              if (status === "success") {
                _updateSubscription(payment.email, payment.payment_date);
              }
              res.json({
                status,
                message,
                trans_id: data.data?.trans_id,
                ref_id: data.data?.ref_id,
              });
            } else {
              console.error(
                "PayChangu Verification API Error:",
                JSON.stringify(data, null, 2)
              );
              if (
                data.message &&
                (data.message.toLowerCase().includes("already") ||
                  data.message.toLowerCase().includes("authenticated") ||
                  data.message.toLowerCase().includes("completed") ||
                  data.message.toLowerCase().includes("successful") ||
                  data.status === "successful")
              ) {
                const status = "success";
                const message = "Payment successful";
                db.run(
                  `UPDATE payments SET status = ?, message = ?, trans_id = ?, ref_id = ? WHERE transaction_id = ?`,
                  [
                    status,
                    message,
                    data.data?.trans_id || null,
                    data.data?.ref_id || null,
                    tx_ref,
                  ],
                  (err) => {
                    if (err)
                      console.error(
                        "Error updating payment status:",
                        err.message
                      );
                  }
                );
                _updateSubscription(payment.email, payment.payment_date);
                res.json({
                  status,
                  message,
                  trans_id: data.data?.trans_id,
                  ref_id: data.data?.ref_id,
                });
              } else {
                throw new Error(data.message || "Verification failed");
              }
            }
            resolve();
          } catch (e) {
            console.error("Verification error:", e.message);
            reject(e);
          }
        }
      );
    });
  } catch (e) {
    res.status(500).json({ error: `Failed to verify payment: ${e.message}` });
  }
});

app.post(
  "/api/paychangu-webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const sig = req.headers["x-paychangu-signature"];
    if (sig) {
      const expectedSig = crypto
        .createHmac("sha256", paychanguSecretKey)
        .update(req.body)
        .digest("hex");
      if (sig !== expectedSig) {
        console.error("Invalid webhook signature:", {
          expected: expectedSig,
          received: sig,
        });
        return res.status(401).json({ error: "Invalid signature" });
      }
    }

    let event;
    try {
      event = JSON.parse(req.body.toString());
      console.log("Received PayChangu webhook event:", event);
    } catch (e) {
      console.error("Invalid webhook payload:", e.message);
      return res.status(400).json({ error: "Invalid webhook payload" });
    }

    if (
      event.status === "success" ||
      event.event_type === "api.charge.payment"
    ) {
      const email = event.customer?.email || event.email;
      const txRef = event.charge_id || event.reference;
      if (email && txRef) {
        db.get(
          "SELECT * FROM payments WHERE transaction_id = ?",
          [txRef],
          (err, payment) => {
            if (err) {
              console.error(
                "Database error fetching payment for webhook:",
                err.message
              );
              return;
            }
            if (payment && payment.status !== "success") {
              db.run(
                `UPDATE payments SET status = ?, message = ?, trans_id = ?, ref_id = ? WHERE transaction_id = ?`,
                [
                  "success",
                  "Payment successful via webhook",
                  event.data?.trans_id || null,
                  event.data?.ref_id || null,
                  txRef,
                ],
                (err) => {
                  if (err) {
                    console.error(
                      "Error updating payment from webhook:",
                      err.message
                    );
                  } else {
                    console.log(
                      `Payment ${txRef} updated to success via webhook`
                    );
                    _updateSubscription(email, new Date().toISOString());
                  }
                }
              );
            } else {
              console.log(`Payment ${txRef} already processed or not found`);
            }
          }
        );
      }
    }

    res.status(200).send("OK");
  }
);

app.get("/return", (req, res) => {
  const { charge_id, status } = req.query;
  console.log("PayChangu return:", { charge_id, status });
  res.send(`
    <html>
      <body>
        <script>
          window.close();
        </script>
        Payment status: ${status}
      </body>
    </html>
  `);
});

function _updateSubscription(email, paymentDate) {
  db.run(
    `INSERT OR REPLACE INTO subscriptions (email, expires, hours_remaining) 
     VALUES (?, datetime(?, '+1 month'), 20)`,
    [email, paymentDate],
    (err) => {
      if (err) {
        console.error("Error updating subscription:", err.message);
      } else {
        console.log(`Subscription updated for ${email}`);
      }
    }
  );
}

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(
    "Endpoints available: /api/register, /api/login, /api/getESP, /api/updateESP, /api/history, /api/hours?period=month, /api/process-payment, /api/verify-payment"
  );
});

process.on("SIGINT", () => {
  db.close((err) => {
    if (err) {
      console.error("Error closing database:", err.message);
    }
    console.log("Database connection closed.");
    process.exit(0);
  });
});
