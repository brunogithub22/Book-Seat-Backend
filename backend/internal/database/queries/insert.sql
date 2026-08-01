-- name: CreatePerson :one
INSERT INTO person (
    user_role,
    user_name,
    surname,
    email
) VALUES (
    $1, $2, $3, $4
)
RETURNING id,user_name,surname; 

-- name: CreateRoom :one
INSERT INTO room(
    room_name,
    flor,
    n_seat
) VALUES (
    $1, $2, $3
)
RETURNING id;

-- name: CreateSeat :one
INSERT INTO seat(
    room_id,
    seat_description
) VALUES (
    $1, $2
)
RETURNING id;

-- name: CreateBook :one
INSERT INTO book(
    title,
    author,
    category,
    book_description
) VALUES (
    $1, $2, $3, $4
)
RETURNING id, title;

-- name: CreateUserRoomBooking :one
INSERT INTO user_room_booking (
    reservation_date,
    room_id,
    user_id
) VALUES (
    $1, $2, $3
)
RETURNING id,reservation_date;

-- name: CreateUserBookManage :one
INSERT INTO user_book_manage (
    book_id,
    user_id
) VALUES (
    $1, $2
)
RETURNING id;

-- name: CreateUserBookBooking :one
INSERT INTO user_book_booking (
    book_id,
    user_id,
    reservation_date,
    expiration_date
) VALUES (
    $1, $2, $3, $4
)
RETURNING id,reservation_date,expiration_date;

-- name: CreateUserSeatBooking :one
INSERT INTO user_seat_booking (
    reservation_date,
    seat_id,
    user_id
) VALUES (
    $1, $2, $3
)
RETURNING id,reservation_date;