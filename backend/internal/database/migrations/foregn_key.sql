Create TABLE user_book_booking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_date TIMESTAMP NOT NULL,
    expiration_date TIMESTAMP NOT NULL,
    book_id UUID NOT NULL REFERENCES book(id),
    user_id UUID NOT NULL REFERENCES person(id)
);

Create TABLE user_book_manage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    book_id UUID NOT NULL REFERENCES book(id),
    user_id UUID NOT NULL REFERENCES person(id)
);

Create TABLE user_room_booking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_date TIMESTAMP NOT NULL,
    room_id UUID NOT NULL REFERENCES room(id),
    user_id UUID NOT NULL REFERENCES person(id)
);

Create TABLE user_seat_booking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_date TIMESTAMP NOT NULL,
    seat_id UUID NOT NULL REFERENCES seat(id),
    user_id UUID NOT NULL REFERENCES person(id)
);