"""empty message

Revision ID: 60a20bc4ec69
Revises: 038803ec4c3a
Create Date: 2021-12-01 00:44:45.280402

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '60a20bc4ec69'
down_revision = '038803ec4c3a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('gender', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'gender')
    # ### end Alembic commands ###
