"""empty message

Revision ID: 2b520b28e95b
Revises: 7041f79d6819
Create Date: 2024-09-25 20:06:21.060678

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '2b520b28e95b'
down_revision = '7041f79d6819'
branch_labels = None
depends_on = None


def upgrade():

    userrolesenum = postgresql.ENUM('super_admin', 'admin', 'user', name='userrolesenum')
    userrolesenum.create(op.get_bind())
    # op.add_column('user',
    #               sa.Column('role', sa.Enum('super_admin', 'admin', 'user', name='userrolesenum'), nullable=False,
    #                         server_default='user'))

    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('clothes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('created_on', sa.DateTime(), server_default=sa.text('now()'), nullable=False))
        batch_op.drop_column('crated_on')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('updated_on', sa.DateTime(), server_default=sa.text('now()'), nullable=False))
        batch_op.add_column(sa.Column('role', sa.Enum('admin', 'user', name='userrolesenum'), nullable=False))
        batch_op.drop_column('update_on')


    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('update_on', postgresql.TIMESTAMP(), server_default=sa.text('now()'), autoincrement=False,
                      nullable=False))
        batch_op.drop_column('role')
        batch_op.drop_column('updated_on')

    with op.batch_alter_table('clothes', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('crated_on', postgresql.TIMESTAMP(), server_default=sa.text('now()'), autoincrement=False,
                      nullable=False))
        batch_op.drop_column('created_on')

    # ### end Alembic commands ###
