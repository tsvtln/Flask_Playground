# from flask import Flask, render_template
#
# app = Flask(__name__)
#
#
# @app.route('/')
# def hello_world():
#     context = {'name': 'Tsetso', 'age': 30}
#     return render_template('index.html', **context)
#
#
# if __name__ == '__main__':
#     app.run()

from flask import Flask, request, g
from flask_restful import Resource, Api
from werkzeug.exceptions import NotFound

app = Flask(__name__)  # creates flask application
api = Api(app)


class BookModel:
    def __init__(self, primary_key, title, author):
        self.primary_key = primary_key
        self.title = title
        self.author = author

    def __str__(self):
        return f"{self.primary_key} Book title: {self.title} from {self.author}."

    def to_dict(self):
        return {"pk": self.primary_key, "title": self.title, "author": self.author}


books = [BookModel(num, f"Title {num}", f"Author {num}") for num in range(1, 6)]
# g.http_status_code_204 = 204

class BooksResource(Resource):
    def get(self):
        return [b.to_dict() for b in books]

    def post(self):
        pk = books[-1].primary_key
        pk += 1
        data = request.get_json()
        book = BookModel(pk, **data)
        books.append(book)

        return book.to_dict()


class BookResource(Resource):
    def get(self, pk):
        try:
            book = [b for b in books if b.primary_key == pk][0]
            return book.to_dict()
        except IndexError:
            # raise NotFound()
            return {"Error": "Requested book is not found!"}, 404

    def put(self, pk):
        data = request.get_json()
        try:
            book = [b for b in books if b.primary_key == pk][0]
            book.title = data['title']
            return book.to_dict()
        except IndexError:
            # raise NotFound()
            return {"Error": "Requested book is not found!"}, 404

    def delete(self, pk):
        try:
            book = [b for b in books if b.primary_key == pk][0]
            books.remove(book)
            return '', 204
        except IndexError:
            # raise NotFound()
            return {"Error": "Requested book is not found!"}, 404

api.add_resource(BooksResource, '/books')
api.add_resource(BookResource, '/books/<int:pk>')
