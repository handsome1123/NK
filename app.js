const express = require('express');
const path = require('path');
const fs = require('fs');
const con = require('./config/db')
const bcrypt = require("bcrypt");
const multer = require('multer');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('express-flash');

// Define storage for the uploaded image
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/img/motorcycles/'); //Uploads will be stored in the 'public/img' directory
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Appendig timestamp to avoid filename conflicts
    }
});

const upload = multer({ storage: storage });

// import MemoryStore
const MemoryStore = require('memorystore')(session);

const app = express();

app.use("/public", express.static(path.join(__dirname, "public")));
app.use(express.json());

app.use(express.urlencoded({ extended: true }));

// for session
app.use(session({
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, //1 day in millisec
    secret: 'mysecretcode',
    resave: false,
    saveUninitialized: true,
    // config MemoryStore here
    store: new MemoryStore({
        checkPeriod: 24 * 60 * 60 * 1000 // prune expired entries every 24h
    })
}));
app.use(passport.initialize());
app.use(passport.session());

// Configure flash middleware
app.use(flash()); // Use express-flash middleware

// Passport local strategy for username/password authentication
passport.use(new LocalStrategy(
    function (username, password, done) {
        const sql = "SELECT UserID as id, Password, Role FROM users WHERE Username = ?";
        con.query(sql, [username], function (err, results) {
            if (err) {
                return done(null, false, { status: 500, message: 'Database server error' });
            }
            if (results.length != 1) {
                return done(null, false, { status: 401, message: 'Incorrect username' });
            }
            // check password
            bcrypt.compare(password, results[0].Password, function (err, same) {
                if (err) {
                    return done(null, false, { status: 503, message: 'Authentication server error' });
                }
                else if (same) {
                    const user = {
                        id: results[0].id,
                        username: username,
                        role: results[0].Role
                    };
                    return done(null, user);
                }
                else {
                    return done(null, false, { status: 400, message: 'Wrong password' });
                }
            });
        });
    }
));


// Serialize user to store in session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser((id, done) => {
    const sql = "SELECT UserID as id, Username, Role FROM users WHERE UserID = ?";
    con.query(sql, [id], function (err, results) {
        if (err || results.length != 1) {
            return done(err);
        }
        const user = {
            id: results[0].id,
            username: results[0].Username,
            role: results[0].Role
        };
        done(null, user);
    });
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// ============ Normal routes =================
// ============ borrower routes =================
// ------------- br-ASSET_LIST --------------
app.get("/br-ASSET_LIST", isAuthenticated, function (req, res) {
    const sql = "SELECT * FROM `motorcycles` WHERE Status = 1";
    con.query(sql, function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
});
// ------------- GET all unablebook --------------
app.get("/unablebook", isAuthenticated, function (req, res) {
    const sql = "SELECT BookingID FROM booking_details WHERE ReturnStatus IN (2, 4) AND BorrowerID = ?;";
    con.query(sql, [req.user.id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
});

// ------------- br-HISTORY --------------
app.get("/br-HISTORY", isAuthenticated, function (req, res) {
    
        const sql = "SELECT bd.BookingID,u1.Username AS BorrowerName,u2.Username AS OwnerName,u3.Username AS StaffName,m.MotorcycleID,m.Model,m.Price,m.MotorcycleImg,DATE_FORMAT(bd.Pickup, '%Y-%m-%d %H:%i:%s') AS Pickup,DATE_FORMAT(bd.Dropoff, '%Y-%m-%d %H:%i:%s') AS Dropoff,bd.ApproverStatus,bd.ReturnStatus FROM booking_details bd JOIN motorcycles m ON bd.MotorcycleID = m.MotorcycleID JOIN users u1 ON bd.BorrowerID = u1.UserID JOIN users u2 ON m.OwnerID = u2.UserID LEFT JOIN users u3 ON bd.StaffID = u3.UserID WHERE bd.BorrowerID = ?;";
        con.query(sql, [req.user.id], function (err, results) {
            if (err) {
                console.error(err);
                return res.status(500).send("Database server error");
            }
            res.json(results);
        });
});

// ------------- br-payment --------------
app.get("/br-payment", isAuthenticated, function (req, res) {
    
    const sql = "SELECT bd.BookingID,u1.Username AS BorrowerName,u2.Username AS OwnerName,u3.Username AS StaffName,m.MotorcycleID,m.Model,m.Price,m.MotorcycleImg,DATE_FORMAT(bd.Pickup, '%Y-%m-%d %H:%i:%s') AS Pickup,DATE_FORMAT(bd.Dropoff, '%Y-%m-%d %H:%i:%s') AS Dropoff,bd.ApproverStatus,bd.ReturnStatus FROM booking_details bd JOIN motorcycles m ON bd.MotorcycleID = m.MotorcycleID JOIN users u1 ON bd.BorrowerID = u1.UserID JOIN users u2 ON m.OwnerID = u2.UserID LEFT JOIN users u3 ON bd.StaffID = u3.UserID WHERE bd.BorrowerID = ?;";
    con.query(sql, [req.user.id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });

});
// ------------- Update a payment --------------
app.get("/update_payment/:BookingID/:MotorcycleID", isAuthenticated, function (req, res) {
    const BookingID = req.params.BookingID;
    const MotorcycleID = req.params.MotorcycleID;
    const sql = "UPDATE `booking_details` SET `ReturnStatus` = '2' WHERE `booking_details`.`BookingID` = ?;";
    const sql1 = "UPDATE `motorcycles` SET `Status` = '3' WHERE `motorcycles`.`MotorcycleID` = ?;";
    con.query(sql, [BookingID], function (err, results) {
        con.query(sql1, [MotorcycleID], function (err, results) {
            if (err) {
                console.error(err);
                return res.status(500).send("Database server error");
            }
            res.send('/HISTORY');
        });
    });
});

// ------------- br-Rent-Motorcycle --------------
app.get("/br-Rent-Motorcycle", isAuthenticated, function (req, res) {
    const sql = "SELECT * FROM `motorcycles` WHERE Status = 1";
    con.query(sql, function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
});
// ---------- bookMotorcycle  -----------
//ส่งคำขอจองรถโดยสร้าง Booking ใหม่และเปลี่ยน Status ของ Motorcycle เป็น PENDING'
app.post('/bookMotorcycle', isAuthenticated, function (req, res) {
    const newBooking = req.body;
    // Insert a new record into the booking_details table
    const sql = "INSERT INTO booking_details SET ?";
    con.query(sql, newBooking, function (err, result) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        const sql1 = "UPDATE motorcycles SET Status = 4 WHERE MotorcycleID =?;";
        con.query(sql1, [newBooking.MotorcycleID], function (err, result) {
            if (err) {
                console.error(err);
                return res.status(500).send("Database server error");
            }
            res.send('/REQUEST_STATUS');
        });
    });
});

// ------------- br-REQUEST_STATUS --------------
app.get("/br-REQUEST_STATUS", isAuthenticated, function (req, res) {
    
    const sql = "SELECT bd.BookingID,u1.Username AS BorrowerName,u2.Username AS OwnerName,u3.Username AS StaffName,m.MotorcycleID,m.Model,m.Price,m.MotorcycleImg,DATE_FORMAT(bd.Pickup, '%Y-%m-%d %H:%i:%s') AS Pickup,DATE_FORMAT(bd.Dropoff, '%Y-%m-%d %H:%i:%s') AS Dropoff,bd.ApproverStatus,bd.ReturnStatus FROM booking_details bd JOIN motorcycles m ON bd.MotorcycleID = m.MotorcycleID JOIN users u1 ON bd.BorrowerID = u1.UserID JOIN users u2 ON m.OwnerID = u2.UserID LEFT JOIN users u3 ON bd.StaffID = u3.UserID WHERE bd.BorrowerID = ?;";
    con.query(sql, [req.user.id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
});

// ============ lender routes =================
// ------------- ld-ASSET_LIST --------------
app.get("/ld-ASSET_LIST", isAuthenticated, function (req, res) {
    const sql = "SELECT m.MotorcycleID, m.Model, u.Username AS Borrowername, m.Status FROM motorcycles m INNER JOIN ( SELECT MotorcycleID, MAX(BookingID) AS MaxBookingID FROM booking_details GROUP BY MotorcycleID ) AS max_bd ON m.MotorcycleID = max_bd.MotorcycleID INNER JOIN booking_details bd ON max_bd.MotorcycleID = bd.MotorcycleID AND max_bd.MaxBookingID = bd.BookingID INNER JOIN users u ON bd.BorrowerID = u.UserID WHERE m.OwnerID = ?;";
    con.query(sql, [req.user.id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
})

// ------------- ld-HISTORY --------------
app.get("/ld-HISTORY", isAuthenticated, function (req, res) {
    const sql = "SELECT bd.BookingID,u1.Username AS BorrowerName,u2.Username AS OwnerName,u3.Username AS StaffName,m.MotorcycleID,m.Model,m.Price,m.MotorcycleImg,DATE_FORMAT(bd.Pickup, '%Y-%m-%d %H:%i:%s') AS Pickup,DATE_FORMAT(bd.Dropoff, '%Y-%m-%d %H:%i:%s') AS Dropoff,bd.ApproverStatus,bd.ReturnStatus FROM booking_details bd JOIN motorcycles m ON bd.MotorcycleID = m.MotorcycleID JOIN users u1 ON bd.BorrowerID = u1.UserID JOIN users u2 ON m.OwnerID = u2.UserID LEFT JOIN users u3 ON bd.StaffID = u3.UserID WHERE bd.BorrowerID = ?;";
    con.query(sql, [req.user.id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
})

// ------------- ld-REQUEST_STATUS --------------
app.get("/ld-REQUEST_STATUS", isAuthenticated, function (req, res) {
    const sql = "SELECT bd.BookingID,u1.Username AS BorrowerName,u2.Username AS OwnerName,u3.Username AS StaffName,m.MotorcycleID,m.Model,m.Price,m.MotorcycleImg,DATE_FORMAT(bd.Pickup, '%Y-%m-%d %H:%i:%s') AS Pickup,DATE_FORMAT(bd.Dropoff, '%Y-%m-%d %H:%i:%s') AS Dropoff,bd.ApproverStatus,bd.ReturnStatus FROM booking_details bd JOIN motorcycles m ON bd.MotorcycleID = m.MotorcycleID JOIN users u1 ON bd.BorrowerID = u1.UserID JOIN users u2 ON m.OwnerID = u2.UserID LEFT JOIN users u3 ON bd.StaffID = u3.UserID WHERE m.OwnerID = ?;";
    con.query(sql, [req.user.id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
})

// ============ staff routes =================
// ------------- st-ASSET_LIST --------------
app.get("/st-ASSET_LIST", isAuthenticated, function (req, res) {
    const sql = "SELECT m.MotorcycleID, m.Model, m.Price, m.OwnerID,m.MotorcycleImg, u1.Username AS Borrowername, u2.Username AS Ownername, m.Status FROM motorcycles m LEFT JOIN (SELECT MotorcycleID, MAX(BookingID) AS MaxBookingID FROM booking_details GROUP BY MotorcycleID) AS max_bd ON m.MotorcycleID = max_bd.MotorcycleID LEFT JOIN booking_details bd ON max_bd.MotorcycleID = bd.MotorcycleID AND max_bd.MaxBookingID = bd.BookingID LEFT JOIN users u1 ON bd.BorrowerID = u1.UserID LEFT JOIN users u2 ON m.OwnerID = u2.UserID;";
        con.query(sql, function (err, results) {
            if (err) {
                console.error(err);
                return res.status(500).send("Database server error");
            }
            res.json(results);
        });
})

// ------------- st-HISTORY --------------
app.get("/st-HISTORY", isAuthenticated, function (req, res) {
    const sql = "SELECT bd.BookingID,u1.Username AS BorrowerName,u2.Username AS OwnerName,u3.Username AS StaffName,m.MotorcycleID,m.Model,m.Price,m.MotorcycleImg,DATE_FORMAT(bd.Pickup, '%Y-%m-%d %H:%i:%s') AS Pickup,DATE_FORMAT(bd.Dropoff, '%Y-%m-%d %H:%i:%s') AS Dropoff,bd.ApproverStatus,bd.ReturnStatus FROM booking_details bd JOIN motorcycles m ON bd.MotorcycleID = m.MotorcycleID JOIN users u1 ON bd.BorrowerID = u1.UserID JOIN users u2 ON m.OwnerID = u2.UserID LEFT JOIN users u3 ON bd.StaffID = u3.UserID ;";
    con.query(sql, function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
})

// ------------- st-RETURN_ASSET --------------
app.get("/st-RETURN_ASSET", isAuthenticated, function (req, res) {
    const sql = "SELECT bd.BookingID,u1.Username AS BorrowerName,u2.Username AS OwnerName,u3.Username AS StaffName,m.MotorcycleID,m.Model,m.Price,m.MotorcycleImg,DATE_FORMAT(bd.Pickup, '%Y-%m-%d %H:%i:%s') AS Pickup,DATE_FORMAT(bd.Dropoff, '%Y-%m-%d %H:%i:%s') AS Dropoff,bd.ApproverStatus,bd.ReturnStatus FROM booking_details bd JOIN motorcycles m ON bd.MotorcycleID = m.MotorcycleID JOIN users u1 ON bd.BorrowerID = u1.UserID JOIN users u2 ON m.OwnerID = u2.UserID LEFT JOIN users u3 ON bd.StaffID = u3.UserID ;";
    con.query(sql, function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        res.json(results);
    });
})


//+++++++++++++++++++++++++++++++++++++++++++
// ---------- password generator -----------
app.get('/password/:pass', function (req, res) {
    const password = req.params.pass;
    bcrypt.hash(password, 10, function (err, hash) {
        if (err) {
            return res.status(500).send("Hashing error");
        }
        res.send(hash);
    });
});

// ----------- Create user -----------
app.post("/createuser", (req, res) => {
    const { username, email_address, password } = req.body;

    // ตรวจสอบว่าข้อมูลที่รับมาครบถ้วนหรือไม่
    if (!username || !email_address || !password) {
        return res.status(400).json({ message: "Missing username, email, or password in request body" });
    }

    bcrypt.hash(password, 10, function (err, hashpassword) {
        if (err) {
            return res.status(500).send("Password error");
        }
        // Insert user into database
        const sql = "INSERT INTO `users` (`UserID`, `Username`, `Password`, `Role`, `Email`, `UserImg`) VALUES (NULL, ?, ?, '3', ?, 'profile.jpg');";
        con.query(sql, [username, hashpassword, email_address], function (err, results) {
            if (err) {
                return res.status(401).send("This username is already taken");
                // return res.status(500).send("Failed to create new user" );
            }
            res.send('/');
        });
    });
});

// ---------- login -----------
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            // Handle error
            console.error('Authentication error:', err);
            return next(err); // Forward error to the next error-handling middleware
        }
        if (!user) {
            req.flash('error', info.message);
            return res.redirect('/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('Login error:', err);
                return next(err);
            }
            req.session.role = user.role;
            return res.redirect('/ASSET_LIST');
        });
    })(req, res, next);
});

// ------------- Update a Approver --------------
app.get("/Approver/:id", function (req, res) {
    const id = req.params.id;
    const sql = "UPDATE booking_details SET ApproverStatus = 1 WHERE BookingID = ?;";
    con.query(sql, [id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        if (results.affectedRows != 1) {
            console.error('Row updated is not 1');
            return res.status(500).send("Update failed");
        }
        res.send("Update succesfully");
    });
});

// ------------- Update a Not Approver --------------
app.get("/NotApprover/:id", function (req, res) {
    const id = req.params.id;
    const sql = "UPDATE booking_details SET ApproverStatus = 2 WHERE BookingID = ?;";
    con.query(sql, [id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        const sql1 = "UPDATE motorcycles SET Status = 1 WHERE MotorcycleID = ( SELECT MotorcycleID FROM booking_details WHERE BookingID = ? );"
        con.query(sql1, [id], function (err, results) {
            if (err) {
                console.error(err);
                return res.status(500).send("Database server error");
            }
            const sql2 = "UPDATE booking_details SET ReturnStatus = 3 WHERE BookingID = ?;"
            con.query(sql2, [id], function (err, results) {
                if (err) {
                    console.error(err);
                    return res.status(500).send("Database server error");
                }
                res.send("Update succesfully");
            });
        });
    });
});

// ------------- Update a Status --------------
app.get("/Status/:id/:status", function (req, res) {
    const id = req.params.id;
    const status = req.params.status;
    const sql = "UPDATE `motorcycles` SET `Status` = ? WHERE `motorcycles`.`MotorcycleID` = ?;";
    con.query(sql, [status, id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        if (results.affectedRows != 1) {
            console.error('Row updated is not 1');
            return res.status(500).send("Update failed");
        }
        res.send("Update succesfully");
    });
});

// ------------- Update a Return --------------
app.get("/Return/:id", function (req, res) {
    const id = req.params.id;
    const sql = "UPDATE `booking_details` SET `ReturnStatus` = '1', `StaffID` = ? WHERE `booking_details`.`BookingID` = ?;";
    con.query(sql, [req.user.id, id], function (err, results) {
        if (err) {
            console.error(err);
            return res.status(500).send("Database server error");
        }
        const sql1 = "UPDATE motorcycles SET Status = 1 WHERE MotorcycleID = (SELECT MotorcycleID FROM booking_details WHERE BookingID = ?);"
        con.query(sql1, [id], function (err, results) {
            if (err) {
                console.error(err);
                return res.status(500).send("Database server error");
            }
            res.send("Return succesfully");
        });
    });
});



// ---------- get user -----------
app.get('/user', function (req, res) {
    res.json({ 'userID': req.user.id, 'username': req.user.username, 'role': req.session.role });

});

// ------------- Logout --------------
app.get("/logout", function (req, res) {
    //clear session variable
    req.session.destroy(function (err) {
        if (err) {
            console.error(err.message);
            res.status(500).send("Cannot clear session");
        }
        else {
            res.redirect("/");
        }
    });
});


// Staff Add
app.post('/staff/add', upload.single('image_uploads'), (req, res) => {
    // Extract data from the form
    const modelName = req.body.model; // Assuming the input field has name="roomName"
    const price = req.body.price;
    const lender = req.body.lender;

    // Perform database insertion

        con.query("INSERT INTO `motorcycles` (`MotorcycleID`, `Model`, `Price`, `Status`, `OwnerID`, `MotorcycleImg`) VALUES (NULL,?,?, '1',?, 'motorcycle.jpg ');", [modelName, price, lender], (err, result) => {
            if (err) {
                console.error('Error inserting room data:', err);
                return res.status(500).json({ message: 'Error adding motorbike' });
            }

            // Respond with success message
            // return res.status(200).json({ message: 'Motorcycle added successfully' });
            return res.redirect('/ASSET_LIST');
        });

});

// Staff edit
// app.post('/staff/edit/:id', upload.single('image_uploads_'), (req, res) => {
//     const MID = req.params.id; // Extract asset ID from URL params
//     const modelName = req.body.Model_;
//     const price = req.body.Price_;
//     const lender = req.body.Lender_;

//     // Extract filename from the path
//     const imagePath = req.file ? path.basename(req.file.path) : null;

//     // Perform database update
//     const sql = "UPDATE motorcycles SET Model = ?, Price = ?, OwnerID = ?, MotorcycleImg = ? WHERE MotorcycleID = ?";
//     con.query(sql, [modelName, price, lender, imagePath, MID], function (err, results) {
//         if (err) {
//             console.error(err);
//             return res.status(500).send("Database server error");
//         }
//         return res.redirect('/ASSET_LIST');
//     });
// });

app.post('/staff/edit/:motorId', upload.single('image_uploads_'), (req, res) => {
    // Extract data from the form
    const motorId = req.params.motorId;
    const { model, price } = req.body;


    // Perform database update operation
    con.query("UPDATE `motorcycles` SET `Model` = ?, `Price` = ?, `OwnerID` = ? WHERE `MotorcycleID` = ?", [model, price, 1, motorId], (err, result) => {
        if (err) {
            console.error('Error updating asset data:', err);
            return res.status(500).json({ message: 'Error updating asset' });
        }

        // Respond with success message
        // return res.status(200).json({ message: 'Asset updated successfully' });
        return res.redirect('/ASSET_LIST');
    });
});








// ============ Page routes =================
// ============ ASSET_LIST routes =================
app.get('/ASSET_LIST', function (req, res) {
    if (req.session.role == 1) {
        res.sendFile(path.join(__dirname, 'views/st-ASSET_LIST.html'));
    }
    else if (req.session.role == 2) {
        res.sendFile(path.join(__dirname, 'views/ld-ASSET_LIST.html'));
    }
    else if (req.session.role == 3) {
        res.sendFile(path.join(__dirname, 'views/br-ASSET_LIST.html'));
    }
    else {
        res.redirect('/');
    }
});

// ============ HISTORY routes =================
app.get('/HISTORY', function (req, res) {
    if (req.session.role == 1) {
        res.sendFile(path.join(__dirname, 'views/st-HISTORY.html'));
    }
    else if (req.session.role == 2) {
        res.sendFile(path.join(__dirname, 'views/ld-HISTORY.html'));
    }
    else if (req.session.role == 3) {
        res.sendFile(path.join(__dirname, 'views/br-HISTORY.html'));
    }
    else {
        res.redirect('/');
    }
});

// ============ PAYMENT routes =================
app.get('/PAYMENT', function (req, res) {
    if (req.session.role == 3) {
        res.sendFile(path.join(__dirname, 'views/br-payment.html'));
    }
    else {
        res.redirect('/ASSET_LIST');
    }
});

// ============ REQUEST_BORROW routes =================
app.get('/REQUEST_BORROW', function (req, res) {
    if (req.session.role == 3) {
        res.sendFile(path.join(__dirname, 'views/br-Rent-Motorcycle.html'));
    }
    else {
        res.redirect('/ASSET_LIST');
    }
});
// ============ REQUEST_STATUS routes =================
app.get('/REQUEST_STATUS', function (req, res) {
    if (req.session.role == 2) {
        res.sendFile(path.join(__dirname, 'views/ld-REQUEST_STATUS.html'));
    }
    else if (req.session.role == 3) {
        res.sendFile(path.join(__dirname, 'views/br-REQUEST_STATUS.html'));
    }
    else {
        res.redirect('/ASSET_LIST');
    }
});
// ============ DASHBOARD routes =================
app.get('/DASHBOARD', function (req, res) {
    if (req.session.role == 1) {
        // Query to count total motorcycles based on status
        con.query('SELECT \
            COUNT(MotorcycleID) AS totalMotorcycles,\
            SUM(CASE WHEN Status = "1" THEN 1 ELSE 0 END) AS totalAvailable, \
            SUM(CASE WHEN Status = "2" THEN 1 ELSE 0 END) AS totalUnavailable, \
            SUM(CASE WHEN Status = "3" THEN 1 ELSE 0 END) AS totalBorrowing, \
            SUM(CASE WHEN Status = "4" THEN 1 ELSE 0 END) AS totalPending \
            FROM motorcycles', function (error, results) {

            if (error) {
                throw error;
            }

            const totalMotorcycles = results[0].totalMotorcycles;
            const totalAvailable = results[0].totalAvailable;
            const totalUnavailable = results[0].totalUnavailable;
            const totalBorrowing = results[0].totalBorrowing;
            const totalPending = results[0].totalPending;

            // Read the HTML file
            fs.readFile(path.join(__dirname, 'views/st-DashBoard.html'), 'utf8', (err, html) => {
                if (err) {
                    throw err;
                }

                // Replace placeholders with the total counts
                html = html.replace('{{totalMotorcycles}}', totalMotorcycles);
                html = html.replace('{{totalAvailable}}', totalAvailable);
                html = html.replace('{{totalUnavailable}}', totalUnavailable);
                html = html.replace('{{totalBorrowing}}', totalBorrowing);
                html = html.replace('{{totalPending}}', totalPending);

                // Send the modified HTML
                res.send(html);
            });
        });
    }

    else if (req.session.role == 2) {
        // Query to count total motorcycles based on status
        con.query(`SELECT \
            COUNT(MotorcycleID) AS totalMotorcycles,\
            SUM(CASE WHEN Status = "1" THEN 1 ELSE 0 END) AS totalAvailable, \
            SUM(CASE WHEN Status = "2" THEN 1 ELSE 0 END) AS totalUnavailable, \
            SUM(CASE WHEN Status = "3" THEN 1 ELSE 0 END) AS totalBorrowing, \
            SUM(CASE WHEN Status = "4" THEN 1 ELSE 0 END) AS totalPending \
            FROM motorcycles WHERE OwnerID = ${req.user.id}`, function (error, results) {

            if (error) {
                throw error;
            }

            const totalMotorcycles = results[0].totalMotorcycles;
            const totalAvailable = results[0].totalAvailable;
            const totalUnavailable = results[0].totalUnavailable;
            const totalBorrowing = results[0].totalBorrowing;
            const totalPending = results[0].totalPending;

            // Read the HTML file
            fs.readFile(path.join(__dirname, 'views/ld-DashBoard.html'), 'utf8', (err, html) => {
                if (err) {
                    throw err;
                }

                // Replace placeholders with the total counts
                html = html.replace('{{totalMotorcycles}}', totalMotorcycles);
                html = html.replace('{{totalAvailable}}', totalAvailable);
                html = html.replace('{{totalUnavailable}}', totalUnavailable);
                html = html.replace('{{totalBorrowing}}', totalBorrowing);
                html = html.replace('{{totalPending}}', totalPending);

                // Send the modified HTML
                res.send(html);
            });
        });
    }
    else {
        res.redirect('/ASSET_LIST');
    }
});

// ++++++++++ staff Dashboard++++++++++//

// ============ RETURN_ASSET routes =================
app.get('/RETURN_ASSET', function (req, res) {
    if (req.session.role == 1) {
        res.sendFile(path.join(__dirname, 'views/st-RETURN_ASSET.html'));
    }
    else {
        res.redirect('/ASSET_LIST');
    }
});

// ============ LOGIN routes =================
app.get('/login', function (_req, res) {
    res.sendFile(path.join(__dirname, 'views/login.html'));
});

// ============ REGISTER routes =================
app.get('/register', function (_req, res) {
    res.sendFile(path.join(__dirname, 'views/register.html'));
});

// ============ HOME routes =================
app.get('/', function (_req, res) {
    res.sendFile(path.join(__dirname, 'views/home.html'));
});

const PORT = 3000;
app.listen(PORT, function () {
    console.log('Server is running at port ' + PORT);
})