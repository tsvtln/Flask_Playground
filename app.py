from flask import Flask, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_migrate import Migrate
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres-user:Levski1914@localhost:5432/store"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To suppress a warning

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


class BookModel(db.Model):
    __tablename__ = 'books'

    pk = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)
    secret_text = db.Column(db.String, nullable=False, default="42", server_default="ok")
    reader_pk = db.Column(db.Integer, db.ForeignKey('readers.pk'))
    reader = db.relationship('ReaderModel')

    def __repr__(self):
        return f"<{self.pk}> {self.title} from {self.author}"

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class BooksResource(Resource):
    def get(self):
        books = BookModel.query.all()
        return [book.as_dict() for book in books], 200

    def post(self):
        data = request.get_json()
        if not data:
            abort(400, description="No input data provided")

        title = data.get('title')
        author = data.get('author')

        if not title or not author:
            abort(400, description="Both 'title' and 'author' fields are required")

        book = BookModel(title=title, author=author)
        db.session.add(book)
        db.session.commit()
        return book.as_dict(), 201


class BookResource(Resource):
    def get(self, pk):
        book = BookModel.query.get(pk)
        if not book:
            abort(404, description=f"Book with pk {pk} not found")
        return book.as_dict(), 200

    def put(self, pk):
        book = BookModel.query.get(pk)
        if not book:
            abort(404, description=f"Book with pk {pk} not found")

        data = request.get_json()
        if not data:
            abort(400, description="No input data provided")

        title = data.get('title')
        author = data.get('author')

        if title:
            book.title = title
        if author:
            book.author = author

        db.session.commit()
        return book.as_dict(), 200

    def delete(self, pk):
        book = BookModel.query.get(pk)
        if not book:
            abort(404, description=f"Book with pk {pk} not found")

        db.session.delete(book)
        db.session.commit()
        return {'message': f'Book with pk {pk} has been deleted.'}, 200


class ReaderModel(db.Model):
    __tablename__ = 'readers'
    pk = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    books = db.relationship("BookModel", backref="book", lazy='dynamic')


api.add_resource(BooksResource, '/books')
api.add_resource(BookResource, '/books/<int:pk>')

if __name__ == '__main__':
    app.run(debug=True)
