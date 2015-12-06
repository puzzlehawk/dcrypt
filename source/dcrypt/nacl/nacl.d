module nacl;

public import dcrypt.nacl.secretbox;
public import dcrypt.nacl.box;

public alias secretbox crypto_secretbox;
public alias secretbox_open crypto_secretbox_open;
public alias box crypto_box;
public alias box_open crypto_box_open;